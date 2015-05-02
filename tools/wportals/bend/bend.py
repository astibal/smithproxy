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
import pylibconfig2 as cfg

from shmtable import ShmTable

PY_MAJOR_VERSION = sys.version_info[0]

import SOAPpy


class LogonTable(ShmTable):             

    def __init__(self):
        ShmTable.__init__(self,4+64+128)
        self.logons = {}
        self.normalizing = True

    def add(self,ip,user,groups):

        self.logons[ip] = [ip,user,groups]
        self.save(True)
        
    def rem(self,ip):
        if ip in self.logons.keys():
            self.logons.pop(ip, None)
            self.save(True)
            
    def save(self, inc_version=False):
        self.seek(0)
        self.clear()
        self.write_header(inc_version,len(self.logons.keys()))
        
        for k in self.logons.keys():
              try:
                  self.write(struct.pack("4s64s128s",socket.inet_aton(k),self.logons[k][1],self.logons[k][2]))
              except IndexError:
                  continue

        self.normalize = False # each dump effectively normalizes db

    def on_new_version(self,o,n):
        self.logons = {}
        
    def on_new_entry(self,blob):
        
        i,u,g = struct.unpack("4s64s128s",blob)
        ip = socket.inet_ntoa(i)
        
        tag = ''
        if ip in self.logons.keys():
            tag = ' (dup)'

        if self.normalizing:
            self.normalize = True

        self.logons[ip] = [ip,u.strip(),g.strip()]
        print "on_new_entry: added " + ip + tag + ", " + u.strip() + ", " + g.strip()
        

        return True

    def on_new_finished(self):
        pass



class TokenTable(ShmTable):
    def __init__(self):
        ShmTable.__init__(self,576)
        self.tokens = {}   # token => url
        self.used_tokens = []  # used throw here - delete when appropriate
        self.active_queue = []    # add everything here. After size grows to some point, start
                               # deleting also active unused yed tokens
    
        self.delete_used_threshold =   5   # 1 means immediately
        self.delete_active_threshold = 200  # mark oldest tokens above this margin as used
    
    def on_new_table(self):
        ShmTable.on_new_table(self)
        self.tokens = {}

    def on_new_entry(self,blob):
        ShmTable.on_new_entry(self,blob)
        t,u = struct.unpack('64s512s',blob)
        
        t_i = t.find('\x00',0,512)
        u_i = u.find('\x00',0,512)
        tt = t[:t_i]
        uu = u[:u_i]
        
        #print "on_new_entry: " + tt + ":" + uu
        self.tokens[tt] = uu
        self.life_queue(tt)
        
    def toggle_used(self,token):
        self.used_tokens.append(token)
        if len(self.used_tokens) > self.delete_used_threshold:
            
            # delete all used tokens from DB
            for t in self.used_tokens:
                print "toggle_used: wiping used token " + t
                self.tokens.pop(t,None)
                
            self.used_tokens = []
            self.save(True)
            

    def life_queue(self,token):
        self.active_queue.append(token)
        
        while len(self.active_queue) > self.delete_active_threshold:
            oldest_token = self.active_queue[0]
            print "life_queue: too many active tokens, dropping oldest one " + oldest_token
            self.toggle_used(oldest_token)
            self.active_queue = self.active_queue[1:]
        
    
    def save(self, inc_version=False):
        self.seek(0)
        self.clear()
        self.write_header(inc_version,len(self.tokens.keys()))
        
        write_cnt = 0
        for k in self.tokens.keys():
              try:
                  self.write(struct.pack("64s512s",k,self.tokens[k]))
                  write_cnt = write_cnt + 1
              except IndexError:
                  continue

        print "save: %d tokens written to table" % (write_cnt,)

        
        self.normalize = False # each dump effectively normalizes db
        



class AuthManager:

    def __init__(self):
      self.logon_shm = None
      self.token_shm = None
      self.global_token_referer = {}
      self.server = SOAPpy.SOAPServer(("localhost", 65456))
      
      self.portal_address = None
      self.portal_port = None
    
      self.user_db = {}
    
    def setup_logon_tables(self,mem_name,mem_size,sem_name):

      self.logon_shm = LogonTable()
      self.logon_shm.setup("/smithproxy_auth_ok",1024*1024,"/smithproxy_auth_ok.sem")
      self.logon_shm.clear()
      self.logon_shm.write_header()

    def setup_token_tables(self,mem_name,mem_size,sem_name):
      self.token_shm = TokenTable()
      self.token_shm.setup("/smithproxy_auth_token",1024*1024,"/smithproxy_auth_token.sem")
      self.token_shm.clear();
      
      # test data
      self.token_shm.seek(0)
      self.token_shm.write(struct.pack('III',1,1,576))
      test1_token = "233474357"
      test1_url   = "idnes.cz"
      self.token_shm.write(struct.pack('64s512s',test1_token,test1_url))

    def cleanup(self):
        self.token_shm.cleanup()
        self.logon_shm.cleanup()



    def token_data(self, token):
        
        print "token_data: start, acquiring semaphore"
        
        self.token_shm.acquire()
        print "token_data: start, semaphore acquired, loading.."
        self.token_shm.load()
        print "token_data: start, token  table loaded"
        self.token_shm.release()
        print "token_data: start, semaphore released"
        
        #print(str(self.token_shm.tokens.keys()))

        # some pretty-printing
        if token in self.token_shm.tokens.keys():
            if token in self.token_shm.used_tokens:
                print "token " + token + " already used"
            else:
                print "token " + token + " found"
        else:
            print "token " + token + " not found ..."


        # say farewell
        if token in self.token_shm.used_tokens:
            return None

        # hit - send a link and invalidate
        if token in self.token_shm.tokens.keys():
            res = self.token_shm.tokens[token]
            self.token_shm.toggle_used(token) # now is token already invalidated, and MAY be deleted
            return res
        
        return None


    def authenticate(self, ip, username, password,token):

        ipa = socket.inet_aton(ip)
        print "authenticate: request: user %s from %s - token %s" % (username,ip,str(token))
        ret = False

        if not username:
            username = '<guest>'
        
        if self.authenticate_check_db(ip,username,password,token):
            print "authenticate: user " + username + " auth successfull from " + ip
            
            #this is just bloody test
            
            self.logon_shm.acquire()
            self.logon_shm.load()       # load new data!
            self.logon_shm.add(ip,username,username+"_group")
            self.logon_shm.release()
            
            # :-D
            ret = True
            if token:
                if token in self.global_token_referer.keys():
                    ref = self.global_token_referer[token]
                    print "token " + token + " global referer: " + ref
                    return ref
                else:
                    return "http://"+self.portal_address+":"+self.portal_port+"/authenticated.html"

        else:
            print "authenticate: user " + username + " auth failed from " + ip


        return ret

    def save_referer(self,token,ref):
        print "incoming referer: " + token + " -> " + ref
        
        self.global_token_referer[token] = ref

    def serve_forever(self):
          self.server.registerFunction(self.authenticate)
          self.server.registerFunction(self.save_referer)
          self.server.serve_forever()

    def load_config_users(self,user_items):
        for user in user_items:
            print "user: " + user[0]
            #print user[1].items()
            
            d = {}
            d["type"] = "static"
            d["username"] = user[0]
            for pair in user[1].items():
                d[pair[0]] = pair[1]
                
            print str(d)
            self.user_db[user[0]] = d

    def authenticate_local_decrypt(self,salt,ciphertext):
        # FIXME!!!
        return ciphertext

    def authenticate_check_db(self,ip,username,password,token):
        
        try:
            if username in self.user_db:
                if "type" in self.user_db[username]:
                    if self.user_db[username]["type"] == "static":
                        if "password" in self.user_db[username]:
                            if self.user_db[username]['password'] == password:
                                return True
                        else:
                            if "encrypted_password" in self.user_db[username]:
                                if authenticate_local_decrypt("ABC",self.user_db[username]['encrypted_password']) == password:
                                    return True
                        
        except KeyError, e:
            pass
        except IndexError, e:
            pass

        return False

def run():   
    c = cfg.Config()
    c.read_file("/etc/smithproxy/smithproxy.cfg")    
    u = cfg.Config()
    u.read_file("/etc/smithproxy/users.cfg")
    
    
    a = AuthManager()
    a.portal_address = c.settings.auth_portal.address
    a.portal_port = c.settings.auth_portal.http_port
    print "Portal settings:"
    print " IP   " + a.portal_address
    print " port " + a.portal_port
    
    print "Loading users"
    a.load_config_users(u.users.items())
    
    a.setup_logon_tables("/smithproxy_auth_ok",1024*1024,"/smithproxy_auth_ok.sem")
    a.setup_token_tables("/smithproxy_auth_token",1024*1024,"/smithproxy_auth_token.sem")
    
    try:
        a.serve_forever()
    except KeyboardInterrupt, e:
        print "Ctrl-C pressed. Wait to close shmem."
        a.cleanup()


run()
