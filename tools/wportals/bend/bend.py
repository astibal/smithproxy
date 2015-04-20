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
from shmtable import ShmTable

PY_MAJOR_VERSION = sys.version_info[0]

import SOAPpy

class LogonTable(ShmTable):
    def __init__(self):
	ShmTable.__init__(self)
	self.logons = {}   # ip -> [user, groupstring ] ... in shm: 32bit,char[64],char[128]
	self.version = 0
	self.header_size = 8 
	
    def write_header(self, inc_version=False):
	self.seek(0)
	self.version = self.version + 1
	self.write(struct.pack('II',self.version,len(self.logons.keys())))
	

    def read_header(self):
	self.seek(0)
	s = self.read(8)
	v,n = struct.unpack('II',s)

	return v,n
      
    def is_updated(self, v):
	if v != self.version:
	   return True
	 
    def ack_updated(self, a):
	self.version = a

    def load(self):
        print "---load:"
	self.seek(0)
	v,n = self.read_header()
	if not self.is_updated(v):
	    print "---same version: %d, entries: %d" % (v,n)
	else:
	    print "---updated version: %d, entries: %d" % (v,n)
	
	    self.logons = {}

	    normalize = False		# should we fix database?
	    for i in range(0,n):
		s = self.read(4+64+128)
		
		ip,u,g = struct.unpack("I64s128s",s)
		
		if ip in self.logons.keys():
		    print "IP %d already in database. will normalize." % (ip,)
		    normalize = True
		    continue
		self.logons[ip] = [ip,u.strip(),g.strip()]
		print str(ip)
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
		  self.write(struct.pack("I64s128s",k,self.logons[k][1],self.logons[k][2]))
	      except IndexError:
		  continue
	


st = LogonTable()
st.setup("/smithproxy_auth_ok",1024,"/smithproxy_auth_ok.sem")
st.clear()
st.write_header()

def authenticate(username, password):

    ret = False
  
    st.acquire()
    
    if username == password:
	st.load()
    else:
	st.seek(0)
	r,n = st.read_header()
	print "current version: %d" % (r,)
	st.read(n*(4+64+128))
	
	# end of entries
	st.write(struct.pack('I64s128s',0xc0a80101,username,"groups_of_"+username))
	st.seek(0)
	st.write(struct.pack('II',r+1,n+1))

	# :-D
	ret = True

    st.release()
    
    return ret
    
    
try:

    server = SOAPpy.SOAPServer(("localhost", 65456))

    server.registerFunction(authenticate)
    server.serve_forever()
    
except KeyboardInterrupt, e:
    print "Ctrl-C pressed. Wait to close shmem."
    st.cleanup()
    
    