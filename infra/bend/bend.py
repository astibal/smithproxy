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

import traceback
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
import auth.ldapaaa as ldapaaa
import auth.ldapcon as ldapcon

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
    

def cfg_to_dict(cfg_element):
    # this is materialization of the shame of pylibconfig2. 
    # It cannot convert ConfigGroup into dictionary. Poor.
    if isinstance(cfg_element,cfg.ConfGroup):
        d = {}
        for c in cfg_element.items():
            k = c[0]
            v = c[1]
            if isinstance(v,cfg.ConfGroup) or isinstance(v,cfg.ConfList):
                v = cfg_2_dict(v)
            d[k] = v
    elif isinstance(cfg_element,cfg.ConfList):
        d = []
        for l in cfg_element:
            d.append(cfg_2_dict(l))
    elif isinstance(cfg_element,tuple):
        d = {}
        if isinstance(cfg_element[1],cfg.ConfGroup) or isinstance(cfg_element[1],cfg.ConfList):
            d[cfg_element[0]] = cfg_2_dict(cfg_element[1])
        else:
            d[cfg_element[0]] = cfg_element[1]
    else:
        return cfg_element

    
    return d

def intersect_lists(l1,l2):
    return [filter(lambda x: x in l1, sublist) for sublist in l2]


def unique_list(l):
    ret = []
    for ll in l:
        if ll not in ret:
            ret.append(ll)
            
    return ret

def unique_prefixes(lst,delim):
    u = []
    
    for l in lst:
        if l.find(delim) >= 0:
            prefix = l.split(delim)
            if prefix not in u:
                u.append(prefix)
    return u
    


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
      self.group_db = {}
      self.identities_db = {}
      self.sources_db = {}
      self.sources_local_db = {}
      self.sources_ldap_db = {}
      
      self.sources_groups = {}
      self.sources_groups['local'] = []
      
      self.address_identities = {}
      self.objects_identities = {}
      
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

    

    def recursive_group_members(self, group):
        non_groups = []
        if group in self.group_db.keys():
            for member in self.group_db[group]["members"]:
                if member.find('local@') >= 0:
                    non_groups.extend(self.recursive_group_members(member.split('local@')[1])) 
                else:
                    non_groups.append(member)
                    
        return non_groups
                    

    def authenticate_check(self, ip, username, password, identities):
        
        if ip not in self.address_identities.keys():
            self.address_identities[ip] = []
            
        ret = 0
        
        for i in identities:
            flog.info("authenticate_check: matching against identity %s " % (i,))
            if i in self.identities_db.keys():
                ii = self.identities_db[i]
                
                for g in ii["groups"]:
                    flog.debug("authenticate_check: checking group %s" % (g,))
                    
                    exploded_members = unique_list(self.recursive_group_members(g))
                    flog.debug("authenticate_check: full member list of %s: %s" % (g,str(exploded_members)))
                    
                    for m in exploded_members:
                        flog.debug("authenticate_check: investigating member target %s" % (m,))

                        source = ''
                        user = ''
                        group = ''
                        is_user = False

                        if m.find(':') >= 0:
                           is_user = True
                            
                        flog.debug("authenticate_check: investigating member target %s: user" % (m,))
                        
                        if is_user:
                            pairlet = m.split(":")
                            source = pairlet[0]
                            user = pairlet[1]
                            
                        elif m.find('@') >= 0:
                            pairlet = m.split("@")
                            source = pairlet[0]
                            group = pairlet[1]
                            
                        
                        if is_user and user != username:
                            continue
                            flog.debug("authenticate_check: investigating member target %s: user doesn't match" % (m,))
                        else:
                            flog.debug("authenticate_check: investigating member target %s: user matches" % (m,))

                            if is_user:
                                ret += self.authenticate_check_local(ip,username,password,identities)
                            else:
                                #flog.debug("authenticate_check: investigating member target %s: non-local users not yet implemented" % (m,))
                                ret += self.authenticate_check_ldap(ip,username,password,identities,m)
                                
                            if ret:
                                flog.debug("authenticate_check: investigating member target %s: authentication OK!" % (m,))
                                ret += 1
                                if i not in self.address_identities[ip]:
                                    self.address_identities[ip].append(i)
                                    
                                flog.debug("authenticate_check: investigating member target %s: looking for other identities" % (m,))
                                if m in self.objects_identities.keys():
                                    for alt_identity in self.objects_identities[m]:
                                        if alt_identity not in self.address_identities[ip]:
                                            flog.debug("authenticate_check: investigating member target %s: alternative identity: %s" % (m,alt_identity))
                                            self.address_identities[ip].append(alt_identity)
                                            ret += 1
                            else:
                                flog.debug("authenticate_check: investigating member target %s: authentication failed!" % (m,))
                                    
        
        if ret > 0:
            return ret
        
        if self.authenticate_check_local(ip,username,password,identities):
            flog.info("authenticate_check: user " + username + " local auth successfull from " + ip + " -- fallback authentication")
            return 1
        
        
        # reset authentication on failure
        self.address_identities[ip] = []
        return 0


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
        
        if self.authenticate_check(ip,username,password,identities) > 0:
            flog.info("authenticate: user " + username + " auth successfull from " + ip)
            
            # normalize identities
            identities_to_send = username
            if ip in self.address_identities.keys():
                x = self.address_identities[ip]
                if len(x) > 0:
                    for i in x:
                        identities_to_send += "+"
                        identities_to_send += i
            
            self.logon_shm.acquire()
            self.logon_shm.load()       # load new data!
            self.logon_shm.add(ip,username,identities_to_send)
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
                
            self.user_db[user[0]] = d
            flog.debug("user: " + user[0] + " -> " + str(d))

    def load_config_groups(self, groups_items):
        flog.debug("groups: ")
        for i in groups_items:
            d = {}
            d["name"] = i[0]
            flog.debug("groups: " + i[0])
            
            for gi in i[1].items():
                
                if gi[0] == "members":
                    if "members" not in d.keys():
                        d["members"] = []
                    
                    # check and append groups into the list
                    for gii in gi[1]:
                        
                        pairlet = gii.split(":")
                        if len(pairlet) > 1:
                            user = pairlet[1]
                            source = pairlet[0]
                            flog.debug("groups: member %s is an user %s in source %s" % (gii,user,source))
                            
                            if source in self.sources_db.keys() or source == "local":
                                flog.debug("groups: member %s source %s check OK" % (gii,source))
                                d["members"].append(str(gii))
                            else:
                                flog.error("groups: member %s source %s check not OK, invalidated" % (gii,source))

                        else:
                            pairlet = gii.split("@")
                            if len(pairlet) > 1:
                                group = pairlet[1]
                                source = pairlet[0]
                                flog.debug("groups: member %s is a group %s in source %s" % (gii,group,source))

                                if source in self.sources_db.keys() or source == "local":
                                    flog.debug("groups: member %s source %s check OK" % (gii,source))
                                    d["members"].append(str(gii))
                                    
                                    ## groups require special care. Since we have flat authentication scheme,
                                    ## we need to gather all groups which we are interested in for each source
                                    ## this is because user can get authenticated with policy requiring membership in "group_A"
                                    ## but later user hits policy which requires membership in "group_B".
                                    ## we have to query all groups at once to avoid unnecessary authentication popups.
                                    
                                    if group not in self.sources_groups[source]:
                                        self.sources_groups[source].append(group)
                                    
                                else:
                                    flog.error("groups: member %s source %s check not OK, invalidated" % (gii,source))
                        
                else:    
                
                    d[pair[0]] = pair[1]

                flog.debug("groups: " + i[0] + " -> " + str(d))
                
            self.group_db[i[0]] = d
            
        for s in self.sources_groups.keys():
            flog.debug("Interesting groups in source %s: %s" % (s,str(self.sources_groups[s])))
            
        

    def load_config_identities(self, identities_items):
        flog.debug("identities: ")

        for i in identities_items:
            d = {}
            d["name"] = i[0]
            flog.debug("identities: " + i[0])
            
            for pair in i[1].items():
                
                if pair[0] == "groups":
                    if "groups" not in d.keys():
                        d["groups"] = []
                    
                    for gi in pair[1]:
                        if str(gi) in self.group_db.keys():
                            flog.debug("identities: referenced group %s in database." % str(gi))
                            d["groups"].append(str(gi))
                            
                            # dereference groups and fill all objects -> identities  
                            # so single object can be identified as member of more identities at once
                            
                            members = unique_list(self.recursive_group_members(gi))
                            for m in members:
                                if m not in self.objects_identities.keys():
                                    self.objects_identities[m] = []
                                    
                                self.objects_identities[m].append(i[0])
                                
                            
                        else:
                            flog.debug("identities: referenced group %s NOT in database." % str(gi))
                        
                else:
                    d[pair[0]] = pair[1]
                    
            flog.debug("identities: " + i[0] + " -> " + str(d))
            self.identities_db[i[0]] = d
            
            
        flog.debug("identities: dereferenced objects -> identities: " + str(self.objects_identities))
              
    def load_config_sources(self,sources_items):
        for si in sources_items:
            source_type = si[0]
            flog.debug("sources: type %s" % (source_type,))
            
            for sii in si[1].items():
                flog.debug("sources: %s (%s)" % (sii[0], source_type,))
                name = sii[0]
                body = sii[1]
                body = cfg_to_dict(body)
                self.sources_db[name] = body
                
                # add this source to interesting groups structure
                self.sources_groups[name] = []
                
                flog.debug("sources: %s (%s) -> %s" % (name, source_type,str(body)))
            
                if source_type == "ldap":
                    self.sources_ldap_db[name] = body
                elif source_type == "local":
                    self.sources_local_db[name] = body
                
            
                

    def authenticate_local_decrypt(self,ciphertext):
        #flog.debug("authenticating user with " + ciphertext)
        return mycrypto.xor_salted_decrypt(ciphertext,self.a1)

    def authenticate_check_local(self,ip,username,password,identities):
        
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


    def authenticate_check_ldap(self,ip,username,password,identities,target):
        
        flog.debug("authenticate_check_ldap: result: start")
        
        if target.find('@') < 0:
            return False

        source = target.split("@")[0]
        group = target.split("@")[1]
        
        user_dn = None
        group_list = []
        
        l = ldapcon.LdapSearch()
        l.updateProfile(self.sources_ldap_db[source])
        l.init()
        if l.bind() != '':
            flog.debug("authenticate: LDAP: searching for user'%s' in '%s'" % (username,target))
            user_dn, group_list = l.authenticate_user(username,password)
            if user_dn:
                flog.debug("authenticate: LDAP: found user'%s' in '%s': DN=%s, GROUPS=%s" % (username,target,user_dn,str(group_list)))
            else:
                flog.error("authenticate: LDAP: unable to find user'%s' in '%s'" % (username,target))
                
        else:
            flog.error("authenticate: LDAP: unable to bind to search for user'%s' in '%s'" % (username,target))
    
        flog.debug("authenticate_check_ldap: result: %s:%s"  % (str(user_dn),str(group_list)))

        if user_dn:
            return True
        
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
    
    flog.debug("loading config file")
    
    
    try:
        a.load_config_sources(u.sources.items())
        a.load_config_users(u.users.items())
        a.load_config_groups(u.groups.items())
        a.load_config_identities(u.identities.items())
    except Exception, e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        flog.error("Error loading config: %s" % (str(e),))
        flog.error("Error loading config: %s" % (repr(traceback.format_tb(exc_traceback)),))
    
    a.setup_logon_tables("/smithproxy_auth_ok",1024*1024,"/smithproxy_auth_ok.sem")
    a.setup_token_tables("/smithproxy_auth_token",1024*1024,"/smithproxy_auth_token.sem")
    
    try:
        a.serve_forever()
    except KeyboardInterrupt, e:
        print "Ctrl-C pressed. Wait to close shmem."
        a.cleanup()

if __name__ == "__main__":
    run_bend()
