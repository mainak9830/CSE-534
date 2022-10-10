#libraries  ----------------------> Part A
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

#Main Recursive function to search over the domains till the answer is found
def search(host, depth, max, server, current_type):
  if(depth > max):
    return [server]
  q = dns.message.make_query(host.split(depth)[1], current_type)
  #print(host.split(depth)[1])
  r = dns.query.udp(q, server)

  
  #print('---'*49)
  servers = []
  #print(r)
  #print("**"*45)
  auth = r.authority
  if(len(r.answer)):
    return [server]
  #Handling SOA record
  if(len(auth) and auth[0].rdtype == dns.rdatatype.SOA):
    return search(host, depth+1, max, server, current_type)
    
    

  for i in r.additional:
    processed = i.to_text().split(' ')
    if(processed[-2] == 'A'):
      servers.append(processed[-1])
  #print(servers)
  #print(r)
  
  if(len(servers) == 0 and len(auth)):
    ret1 = mydig(auth[0][0].to_text(),current_type)
    return search(host, depth+1, max, ret1[0], current_type)
  if(depth == max):
    
    return servers
  #print(servers)
  
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
      ret = search(hostname, 2, n, root, "A")
      if(len(ret) > 0):
        break
    
    #final query
    server = ret[0]  #Name Server .com

    q = dns.message.make_query(hostname, final_type)
    r = dns.query.udp(q, server)
    ans = []
    #print(r)
    quest = r.question[0].to_text()
    #Handling CNAME record and calling mydig() to resolve the record to get ip
    if(type == "A" and r.answer[0].rdtype == dns.rdatatype.CNAME):
      n_host = r.answer[0][0].to_text()
      #print(host," ", n_host)
      return mydig(n_host, "A")
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
    print("Query time: ", round(time_taken*1000,5)," msec")
    print("WHEN: ", dt.strftime("%a %b %d %H:%M:%S %Y\n"))
    print("MSG SIZE rcvd: ", msize)
    return time_taken
    
    
      

#input
if __name__ == "__main__":
    host = sys.argv[1]
    type = sys.argv[2]
    DNSresolver(host, type)
    