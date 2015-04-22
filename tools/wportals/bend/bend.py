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
	ShmTable.__init__(self,4+64+128)
	self.logons = {}
	self.normalizing = True

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

	self.normalize = False # each dump effectively normalizes db

    def on_new_version(self,o,n):
	self.logons = {}
	
    def on_new_entry(self,blob):
	ShmTable.on_new_entry(self)
	
	ip,u,g = struct.unpack("4s64s128s",blob)
	
	if ip in self.logons.keys():
	    print "IP %s already in database. will rewrite older entries." % (socket.inet_ntoa(ip),)
	    self.logons.pop(ip,None)
	    if self.normalizing:
		self.normalize = True

	self.logons[ip] = [ip,u.strip(),g.strip()]
	print socket.inet_ntoa(ip)
	print u.strip()
	print g.strip()      

    def on_new_finished(self):
	pass



class TokenTable(ShmTable):
    def __init__(self):
        ShmTable.__init__(self,576)
	self.tokens = {}   # token => url
    
    def on_new_table(self):
	ShmTable.on_new_table(self)
	self.tokens = {}

    def on_new_entry(self,blob):
	ShmTable.on_new_entry(self,blob)
	t,u = struct.unpack('64s512s',blob)
        self.tokens[t] = u
	


st = LogonTable()
st.setup("/smithproxy_auth_ok",1024*1024,"/smithproxy_auth_ok.sem")
st.clear()
st.write_header()

su = TokenTable()
su.setup("/smithproxy_auth_tok",1024*1024,"/smithproxy_auth_tok.sem")
su.clear();

su.seek(0)
su.write(struct.pack('III',1,1,576))
test1_token = "233474357"
test1_url   = "idnes.cz"
su.write(struct.pack('64s512s',test1_token,test1_url))
su.load()

def token_url(token):
    if(token == test1_token):
	  return test1_url
	
    return "www.root.cz"


def authenticate(username, password,token, _SOAPContext = None):

    ip  = _SOAPContext.connection.getpeername()[0]
    ipa = socket.inet_aton(ip)
    print "user IP is %s (%s)" % (ip,str(ipa))
    if token:
	print "   token %s" % str(token)
    
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
	if token:
	    ret = token_url(token)

    
    st.release()
    
    return ret
    
    
try:

    server = SOAPpy.SOAPServer(("localhost", 65456))

    server.registerFunction( SOAPpy.MethodSig(authenticate, keywords=0, context=1))
    server.serve_forever()
    
except KeyboardInterrupt, e:
    print "Ctrl-C pressed. Wait to close shmem."
    st.cleanup()
    su.cleanup()
    
    