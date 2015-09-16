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
import logging
import auth.crypto as mycrypto

from shmtable import ShmTable

PY_MAJOR_VERSION = sys.version_info[0]

import SOAPpy


BEND_LOGFILE="/var/log/smithproxy_bend.log"
BEND_KEYFILE="/etc/smithproxy/users.key"

flog = logging.getLogger('bend')
hdlr = logging.FileHandler(BEND_LOGFILE)
formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
hdlr.setFormatter(formatter)
flog.addHandler(hdlr) 
flog.setLevel(logging.INFO)


def cfgloglevel_to_py(cfglevel):
    if(cfglevel >= 7):
        return logging.DEBUG
    elif(cfglevel >= 5):
        return logging.INFO
    elif(cfglevel == 4):
        return logging.WARNING
    elif(cfglevel == 3):
        return logging.ERROR
    else:
        return logging.FATAL
    

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
                  flog.warning("LogonTable: IndexError: not in logons: " + k + " " + str(e))
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
        flog.debug("on_new_entry: added " + ip + tag + ", " + u.strip() + ", " + g.strip())
        

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
        
        flog.info("TokenTable::on_new_entry: " + tt + ":" + uu)
        self.tokens[tt] = uu
        self.life_queue(tt)
        
    def toggle_used(self,token):
        self.used_tokens.append(token)
        if len(self.used_tokens) > self.delete_used_threshold:
            
            # delete all used tokens from DB
            for t in self.used_tokens:
                flog.debug("toggle_used: wiping used token " + t)
                self.tokens.pop(t,None)
                
            self.used_tokens = []
            self.save(True)
            

    def life_queue(self,token):
        self.active_queue.append(token)
        
        while len(self.active_queue) > self.delete_active_threshold:
            oldest_token = self.active_queue[0]
            flog.debug("life_queue: too many active tokens, dropping oldest one " + oldest_token)
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

        flog.debug("save: %d tokens written to table" % (write_cnt,))

        
        self.normalize = False # each dump effectively normalizes db
        



class AuthManager:

    def __init__(self):
      self.logon_shm = None
      self.token_shm = None
      self.global_token_referer = {}
      self.server = SOAPpy.ThreadingSOAPServer(("localhost", 65456))
      
      self.portal_address = None
      self.portal_port = None
    
      self.user_db = {}
      self.a1 = None


    def load_a1(self):
        try:
            f = open(BEND_KEYFILE,"r")
            a = f.read()
            if a:
                self.a1 = a
            f.close()
        except IOError, e:
            flog.error("cannot open a1 file: " + str(e))
    
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
        
        flog.debug("token_data: start, acquiring semaphore")
        
        self.token_shm.acquire()
        flog.debug("token_data: start, semaphore acquired, loading..")
        self.token_shm.load()
        flog.debug("token_data: start, token  table loaded")
        self.token_shm.release()
        flog.debug("token_data: start, semaphore released")
        
        #print(str(self.token_shm.tokens.keys()))

        # some pretty-printing
        if token in self.token_shm.tokens.keys():
            if token in self.token_shm.used_tokens:
                flog.warning("token " + token + " already used")
            else:
                flog.debug("token " + token + " found")
        else:
            flog.debug("token " + token + " not found ...")


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
        flog.debug("authenticate: request: user %s from %s - token %s" % (username,ip,str(token)))
        ret = False
        identities = None


        self.token_shm.acquire()
        self.token_shm.load()
        self.token_shm.release()

        if token in self.token_shm.tokens.keys():
            res = self.token_shm.tokens[token]
            flog.debug("authenticate: token data: " + str(res))
            
            token_data = res.split(" |")
            if len(token_data) > 1:
                identities = token_data[1:]
                flog.debug("authenticate: token identities: " + str(identities))
                
        else:
            flog.warning("authenticate: token data not received")

        flog.info("authenticate: request for user %s from %s - against identities %s" % (username,ip,str(identities)))

        if not username:
            username = '<guest>'
        
        if self.authenticate_check_db(ip,username,password,token):
            flog.info("authenticate: user " + username + " auth successfull from " + ip)
            
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
                    flog.debug("token " + token + " global referer: " + ref)
                    return ref
                else:
                    return "http://"+self.portal_address+":"+self.portal_port+"/authenticated.html"

        else:
            flog.warning("authenticate: user " + username + " auth failed from " + ip)


        return ret

    def save_referer(self,token,ref):
        flog.debug("incoming referer: " + token + " -> " + ref)
        
        self.global_token_referer[token] = ref

    def serve_forever(self):
        
        flog.info("Launching portal on " + self.portal_address + ":" + str(self.portal_port))
        self.server.registerFunction(self.authenticate)
        self.server.registerFunction(self.save_referer)
        self.server.serve_forever()

    def load_config_users(self,user_items):
        for user in user_items:
            flog.debug("user: " + user[0])
            #print user[1].items()
            
            d = {}
            d["type"] = "static"
            d["username"] = user[0]
            for pair in user[1].items():
                d[pair[0]] = pair[1]
                
            print str(d)
            self.user_db[user[0]] = d

    def authenticate_local_decrypt(self,ciphertext):
        #flog.debug("authenticating user with " + ciphertext)
        return mycrypto.xor_salted_decrypt(ciphertext,self.a1)

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
                                if self.authenticate_local_decrypt(self.user_db[username]['encrypted_password']) == password:
                                    return True
                        
        except KeyError, e:
            pass
        except IndexError, e:
            pass

        return False



def run_bend():
    c = cfg.Config()
    c.read_file("/etc/smithproxy/smithproxy.cfg")    
    u = cfg.Config()
    u.read_file("/etc/smithproxy/users.cfg")
    
    
    a = AuthManager()
    a.load_a1()
    a.portal_address = c.settings.auth_portal.address
    a.portal_port = c.settings.auth_portal.http_port
    flog.setLevel(cfgloglevel_to_py(c.settings.log_level));
    
    flog.debug("Loading users")
    a.load_config_users(u.users.items())
    
    a.setup_logon_tables("/smithproxy_auth_ok",1024*1024,"/smithproxy_auth_ok.sem")
    a.setup_token_tables("/smithproxy_auth_token",1024*1024,"/smithproxy_auth_token.sem")
    
    try:
        a.serve_forever()
    except KeyboardInterrupt, e:
        print "Ctrl-C pressed. Wait to close shmem."
        a.cleanup()

if __name__ == "__main__":
    run_bend()
