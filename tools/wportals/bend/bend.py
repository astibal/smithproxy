"""
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.  """

import time
import mmap
import os
import sys
import struct
import posix_ipc
import socket

from shmtable import ShmTable

PY_MAJOR_VERSION = sys.version_info[0]

import SOAPpy

class LogonTable(ShmTable):
    def __init__(self):
	ShmTable.__init__(self)
	self.logons = {}   # ip -> [user, groupstring ] ... in shm: 32bit,char[64],char[128]
	self.version = 0
	self.header_size = 12
	self.row_size = 4+64+128
	
    def write_header(self, inc_version=False):
	self.seek(0)
	
	if inc_version:
            self.version = self.version + 1

	self.write(struct.pack('III',self.version,len(self.logons.keys()),self.row_size))
	

    def read_header(self):
	self.seek(0)
	s = self.read(self.header_size)
	version,no_entries,rowsize = struct.unpack('III',s)

	return version,no_entries,rowsize
      
    def is_updated(self, v):
	if v != self.version:
	   return True
	 
    def ack_updated(self, a):
	self.version = a

    def load(self):
        print "---load:"
	self.seek(0)
	v,n,r = self.read_header()
	
	if r != self.row_size:
            print "Incompatible rowsize! Expecting %d, got %d" % (self.row_size,r)
            return False
	
	if not self.is_updated(v):
	    print "---same version: %d, entries: %d, rowsize: %s" % (v,n,r)
	else:
	    print "---updated version: %d, entries: %d" % (v,n)
	
	    self.logons = {}

	    normalize = False		# should we fix database?
	    for i in range(0,n):
		s = self.read(self.row_size)
		
		ip,u,g = struct.unpack("4s64s128s",s)
		
		if ip in self.logons.keys():
		    print "IP %s already in database. will rewrite older entries." % (socket.inet_ntoa(ip),)
		    self.logons.pop(ip,None)
		    normalize = True

		self.logons[ip] = [ip,u.strip(),g.strip()]
		print socket.inet_ntoa(ip)
		print u.strip()
		print g.strip()

	    self.ack_updated(v)
	    
	    if normalize:
		self.dump()
		print "NORMALIZED"
	    
    def add(self,ip,user,groups):
	if ip in self.logons.keys():
	    return False
	
	
	self.logons[ip] = [ip,user,groups]
	self.dump(True)
	
    def rem(self,ip):
	if ip in self.logons.keys():
	    self.logons.pop(ip, None)
	    self.dump(True)
	    
    def dump(self, inc_version=False):
	self.seek(0)
	self.clear()
	self.write_header(inc_version)
	for k in self.logons.keys():
	      try:
		  self.write(struct.pack("4s64s128s",k,self.logons[k][1],self.logons[k][2]))
	      except IndexError:
		  continue
	


st = LogonTable()
st.setup("/smithproxy_auth_ok",1024,"/smithproxy_auth_ok.sem")
st.clear()
st.write_header()

def authenticate(username, password,_SOAPContext = None):

    ip  = _SOAPContext.connection.getpeername()[0]
    ipa = socket.inet_aton(ip)
    print "user IP is %s (%s)" % (ip,str(ipa))
    
    ret = False
  
    st.acquire()
    
    if username == password:
	st.load()
    else:
        
        #this is just bloody test
        
	st.seek(0)
	r,n,s = st.read_header()
	print "current version: %d" % (r,)
	st.read(n*(4+64+128))
	
	# end of entries
	st.write(struct.pack('4s64s128s',ipa,username,"groups_of_"+username))
	st.seek(0)
	st.write(struct.pack('III',r+1,n+1,st.row_size))

	# :-D
	ret = True

    st.release()
    
    return ret
    
    
try:

    server = SOAPpy.SOAPServer(("localhost", 65456))

    server.registerFunction( SOAPpy.MethodSig(authenticate, keywords=0, context=1))
    server.serve_forever()
    
except KeyboardInterrupt, e:
    print "Ctrl-C pressed. Wait to close shmem."
    st.cleanup()
    
    