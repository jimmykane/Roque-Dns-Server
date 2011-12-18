#!/usr/bin/python
import socket
import threading
import thread
import time
def run_thread (threadname, sleeptime):

  global threadcount, activethreads, threadlock, ip,dataip
  threadlock.acquire() 
  try:

    while 1:
      dataip = socket.gethostbyname_ex("www.google.com") # Edit the www.google.com to your domain name
      ip = str(dataip[2]).strip('[]')
      ip=ip[1:15] 
      print  "Resolving Domain  -> ip[%s]" % ip  
      time.sleep(sleeptime) 
      
  except: 
    print "%s error...." % (threadname)
    activethreads = activethreads - 1
    threadlock.release()
  

class DNSQuery:

  def __init__(self, data):
    self.data=data
    self.dominio=''

    tipo = (ord(data[2]) >> 3) & 15   # Opcode bits

    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])

      while lon != 0:

        self.dominio+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def respuesta(self, ip):

    packet=''

    if self.dominio:

      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP

    return packet

if __name__ == '__main__':  

  #If you want static IP for your server then modify and uncomment the line below
  #ip='192.168.1.1'
  from threading import Timer
  ip='0'
  activethreads = 1
  threadlock = thread.allocate_lock()  
  thread.start_new_thread(run_thread, ("DnsResolver", 50))  #50 coresponds to the refresh interval in seconds
  print 'pyminifakeDNS:: dom.query. 60 IN A %s' % ip  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))

  try:

    while 1:

      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      udps.sendto(p.respuesta(ip), addr)
      print 'Spoofing: %s -> %s' % (p.dominio, ip)

  except  KeyboardInterrupt:

    udps.close()
    print '\nClosing Connections -> [OK] '

  print 'All done Bye bye'

