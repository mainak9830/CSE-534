#libraries  ----------------------> Part B
import time
import dns.name
import dns.rdatatype
import dns.query
from datetime import datetime
import sys

#root servers

root_Servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
                    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
                    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
                    "202.12.27.33"]

#Root signing keys
root_signing_keys = ["19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5", "20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"]

#Query function using TCP
def doquery(domain, server, type, flag = False):
  q = dns.message.make_query(domain, type, want_dnssec=True)
  r = dns.query.tcp(q, server)
  
  #print(domain, "\t", type, " ", server, "\n")
  #print(r)
  return r

#Root validation by comparing hash(KSK) and root KSK and validates RRrecord, RRsig
def rootValidation(KSK, rrsig, rrset):
  valid = False
  hash_ksk = dns.dnssec.make_ds('.', KSK, 'sha256')
  
  for key in root_signing_keys:
    if(key == str(hash_ksk)):
      
      valid = True
      break
  
  if(not valid):
    print("DNSSEC verification failed")
    
  
  try:
    dns.dnssec.validate(rrset, rrsig, {dns.name.from_text('.') : rrset})
    return True
  except:
    print("DNSSEC verification failed")
    return False
  
  return valid
#Parsing DS record, hash_algo, RRrecord, RRsig from authority section of response
def parseAuthority(res):
  DS = None
  hash_algo = None
  
  
  for i in res:
    if i.rdtype == 43:
      for item in i:
        DS = item
        
      break
  if(DS == None):
    print("DNSSEC not supported")
    quit()
  hash_algo = 8    
  return DS, hash_algo,res[0],res[2]
#Parsing RRsig from answer section of response
def parseSig(r):
  for i in r:
    if(i.rdtype == dns.rdatatype.RRSIG):
      return i
  return None
#Parsing KSK, ZSK and RRrecord from authority section of response
def parseKey(r):
  KSK = None
  ZSK = None
  for key in r[0]:
    if(key.flags == 257):
      KSK = key
    if(key.flags == 256):
      ZSK = key
      
  if(not(KSK and ZSK)):
    print("DNSSEC not supported") 
    return []     
  return KSK, ZSK, r[0]
#Validates RRset using RRsig and key
def validateDNSRec(domain, rrsig, rrset, key):
  try:
    dns.dnssec.validate(rrset, rrsig, {domain : key})
    return True
  except:
    print("DNSSEC verification failed")
    return False
  
#Validate the child's hash(KSK) == Parent's DS record
def validate(domain, KSK, hash_algo, prev_ds):
  #print(KSK, " ", domain)
  algo = 'sha256'
  if(hash_algo == '2'):
    algo = 'sha256'
  if(hash_algo == '1'):
    algo = 'sha1'
  valid = False
  hash = dns.dnssec.make_ds(domain, KSK, algo)
  #print(hash,"\n", prev_ds)
  if(hash == prev_ds):
    valid = True
  
  if(not valid):
    print("DNSSEC verification failed")
    quit()
    return False
  return True

#Main Recursive function to search over the domains till the answer is found
def search(host, depth, max, server, current_type):
  if(depth > max):
    return [server]
  r = doquery(host.split(depth)[1], server, current_type, True)
  DS, hash_algo, rrecord, rrrecordsig = parseAuthority(r.authority)
  #print(DS, hash)
  #print(depth)
  #print([server])
  
  #print('---'*49)
  servers = []
  #print(r)
  #print("**"*45)
  
  auth = r.authority
  if(len(r.answer)):
    return [server]
  if(len(auth) and auth[0].rdtype == dns.rdatatype.SOA):
    return [server]
    
    

  for i in r.additional:
    processed = i.to_text().split(' ')
    if(processed[-2] == 'A'):
      servers.append(processed[-1])
  #print(servers)
  #print(r)
  
  if(len(servers) == 0 and len(auth)):
    ret1 = mydig(auth[0][0].to_text(),current_type)
    #rdns = doquery(host.split(depth)[1], ret1.answer[0][0].to_text(), current_type, True)
    rdns = doquery(host.split(depth)[1], ret1[0], current_type, True)
    KSK, ZSK, rrset = parseKey(rdns.answer)
    #print("KSK--",KSK, "\n", "ZSK--",ZSK, "\n","DS--", DS)
    rrsig = parseSig(rdns.answer)
    if(not validateDNSRec(host.split(depth)[1], rrsig, rrset, rrset)):
      pass
    if(not validate(host.split(depth)[1], KSK, hash_algo, DS)):
      pass
    return search(host, depth+1, max, ret1[0], current_type)
  if(depth == max):
    
    return servers
  #print(servers)
  rdns = doquery(host.split(depth)[1], servers[0], current_type, True)
  KSK, ZSK, rrset = parseKey(rdns.answer)
  #print("KSK--",KSK, "\n", "ZSK--",ZSK, "\n","DS--", DS)
  rrsig = parseSig(rdns.answer)
  if(not validateDNSRec(host.split(depth)[1], rrsig, rrset, rrset)):
    pass
  if(not validate(host.split(depth)[1], KSK, hash_algo, DS)):
    pass
  
  #Calling next domain servers
  for server_t in servers:
    ret = search(host, depth+1, max, server_t, current_type)
    #print(ret)
    #print(type(ret))
    if(len(ret) > 0):
      return ret

  return []

#Root calling function and finally making the call the actual name server
def mydig(host, type):
    #root = "192.12.94.30" #com NS
    #root = "216.239.34.10" #google.com NS
    #host = ""
    hostname = dns.name.from_text(host)
    final_type = type
    
    n = len(hostname.labels)
    #print(n)
    for root in root_Servers:
      rdnskey = doquery(dns.name.from_text("."), root, dns.rdatatype.DNSKEY, flag = True)
      #parseAuthority(rrecord.authority)
      KSK, ZSK, rset = parseKey(rdnskey.answer)
      #print(KSK)
      rsig = parseSig(rdnskey.answer)
      rootValidation(KSK, rsig, rset)
      ret = search(hostname, 2, n, root, dns.rdatatype.DNSKEY)
      if(len(ret) > 0):
        break
    
    #final query
    
    server = ret[0]  #Name Server .com
    q = dns.message.make_query(hostname, final_type)
    r = dns.query.udp(q, server)
    ans = []
    #print(r)

    #Handling CNAME record and calling mydig() to resolve the record to get ip
    if(type == "A" and r.answer[0].rdtype == dns.rdatatype.CNAME):
      n_host = r.answer[0][0].to_text()
      #print(host," ", n_host)
      return mydig(n_host, "A")
    #print(r)
    
    for item in r.answer[0]:
      ans.append(item.to_text())
    return ans

  
  
#Collects the result and output the result
def DNSresolver(host, type = "A"):
    start_time = time.time()
    ans = mydig(host, type)
    
    time_taken = time.time() - start_time
    

    print("QUESTION SECTION")
    print(host, " "*6, "IN", " "*3, type)
    msize = str(sys.getsizeof(ans))
    print("\n")
    print("ANSWER SECTION")
    dt = datetime.now()

    for i in ans:
      print(host, " "*6, "IN", " "*3, type, " "*4, i)
    print("\n")
    print("Query time: ", round(time_taken,5)," sec")
    print("WHEN: ", dt.strftime("%a %b %d %H:%M:%S %Y\n"))
    print("MSG SIZE rcvd: ", msize)
    
      

#inputs
if __name__ == "__main__":
    #host = "www.dnssec-failed.org"
    host = sys.argv[1]
    type = "A"
    DNSresolver(host, type)