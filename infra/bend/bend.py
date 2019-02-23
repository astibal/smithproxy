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
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
    """

import traceback
import time
import os
import sys
import logging
import struct
import socket
import binascii
import threading

import posix_ipc
import pylibconfig2 as cfg
import SOAPpy
import json

import auth.crypto as mycrypto
import auth.ldapaaa as ldapaaa
import auth.ldapcon as ldapcon

from logontable import LogonTable
from tokentable import TokenTable
from shmtable import ShmTable

from bendutil import *

PY_MAJOR_VERSION = sys.version_info[0]


def address_version(ip):
    try:
        a = socket.inet_pton(socket.AF_INET, ip)
        return 4
    except socket.error:
        pass

    try:
        a = socket.inet_pton(socket.AF_INET6, ip)
        return 6
    except socket.error:
        pass

    return 0


class AdminManager:

    def __init__(self, logger):
        self.log = logger
        self.admin_tokens = {}  # token -> {created,valid_till,username,ip}
        self.validity = 60

    def issue_token(self, username, ip):

        if not username or not ip or username == "" or ip == "":
            self.log.error("refusing to issue token to unknown identity")
            return -1

        token = str(binascii.hexlify(os.urandom(32)))
        while True:
            if token not in self.admin_tokens.keys():
                break
            token = str(binascii.hexlify(os.urandom(32)))

        now = time.time()
        self.admin_tokens[token] = {}
        self.admin_tokens[token]["created"] = now
        self.admin_tokens[token]["valid_till"] = now + self.validity
        self.admin_tokens[token]["username"] = username
        self.admin_tokens[token]["ip"] = ip

        self.log.info("admin: token %s has been issued to administrator %s at %s" % (token, username, ip,))

        return token

    def use_token(self, token):

        if token in self.admin_tokens.keys():
            username = self.admin_tokens[token]["username"]
            ip = self.admin_tokens[token]["ip"]

            now = time.time()
            if self.admin_tokens[token]["valid_till"] < now:
                self.log.info("admin: token %s for administrator %s at %s expired" % (token, username, ip,))
                del self.admin_tokens[token]
                return False

            self.log.info("admin: token %s for administrator %s at %s refreshed" % (token, username, ip,))
            self.admin_tokens[token]["valid_till"] = now + self.validity
            return True

        return False

    def remove_token(self, token):

        if token in self.admin_tokens.keys():
            username = self.admin_tokens[token]["username"]
            ip = self.admin_tokens[token]["ip"]
            self.log.info("admin: token %s for administrator %s at %s removed" % (token, username, ip,))
            del self.admin_tokens[token]


class AuthConfig(object):

    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')

    def __init__(self, logger=None):

        if not logger:
            self.log = logging.getLogger()
            self.log.setLevel(logging.INFO)

            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.INFO)
            handler.setFormatter(AuthConfig.formatter)
            self.log.addHandler(handler)
        else:
            self.log = logger

        self.a1 = None

        self.log_file = "/var/log/smithproxy_bend.log"

        self.key_file = None
        self.user_file = None
        self.user_cfg = None

        self.sx_file = None
        self.sx_cfg = None

        self.tenant_name = "default"
        self.tenant_index = 0
        self.bend_port = 64000

        self.user_file_mtime = 0
        self.key_file_mtime = 0

    @staticmethod
    def create_logger(log_file=None, to_stdout=False):

        log = logging.getLogger('bend')
        log.handlers = []

        if not log_file or to_stdout:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.INFO)
            handler.setFormatter(AuthConfig.formatter)

        if log_file:
            hdlr = logging.FileHandler(log_file)
            hdlr.setFormatter(AuthConfig.formatter)
            log.addHandler(hdlr)

        log.setLevel(logging.INFO)

        return log

    def set_logger(self, log_file):
        self.log = AuthConfig.create_logger(log_file)

    def load_key(self):
        try:
            f = open(self.key_file, "r")
            a = f.read()
            if a:
                self.a1 = a
            f.close()
        except IOError as e:
            self.log.error("cannot open key file: " + str(e))

    def authenticate_local_decrypt(self, ciphertext):
        return mycrypto.xor_salted_decrypt(ciphertext, self.a1)

    def authenticate_local_encrypt(self, plaintext):
        return mycrypto.xor_salted_encrypt(plaintext, self.a1)

    def set_filenames(self, tenant_name=None):

        self.sx_file = "/etc/smithproxy/smithproxy.cfg"
        self.user_file = "/etc/smithproxy/users.cfg"
        self.key_file = "/etc/smithproxy/users.key"
        self.tenant_name = "default"

        # check if there is specific tenant user.cfg
        if tenant_name:

            # USERS CFG
            try:
                self.tenant_name = tenant_name
                tenant_user_file = "/etc/smithproxy/users." + tenant_name + ".cfg"
                s = os.stat(tenant_user_file)
                self.user_file = tenant_user_file

                if self.log:
                    self.log.info("Tenant user file: " + self.user_file)

            except OSError:
                if self.log:
                    self.log.info("Tenant is using default user file: " + self.user_file)


            # KEY CFG
            try:
                tenant_key_file = "/etc/smithproxy/users." + tenant_name + ".key"
                s = os.stat(tenant_key_file)
                self.key_file = tenant_key_file

            except OSError:
                self.log.info("Tenant is using default key file: " + self.key_file)


            # SX CFG
            try:
                tenant_sx_file = "/etc/smithproxy/smithproxy." + tenant_name + ".cfg"
                s = os.stat(tenant_sx_file)
                self.sx_file = tenant_sx_file

            except OSError:
                self.log.info("Tenant is using default  sx file: " + self.key_file)

        return self.key_file, self.user_file, self.sx_file

    @staticmethod
    def load_users_file(user_file):
        u = cfg.Config()

        flat_file = None
        config_struct = None

        with open(user_file, 'r') as myfile:
            flat_file = myfile.read()

        u.read_string(flat_file)
        config_struct = u

        return flat_file, config_struct

    def load_users(self):

        flat, c_struct = AuthConfig.load_users_file(self.user_file)
        self.user_cfg = c_struct

    def save_users(self):
        if self.user_cfg and self.user_file:
            self.log.info("saving new user file: " + self.user_file)
            with open(self.user_file, 'w') as f:

                f.write(str(self.user_cfg))
                f.close()

            self.log.info("done")
            return True
        else:
            return False



    @staticmethod
    def load_sx_file(sx_file):

        s = cfg.Config()
        with open(sx_file, 'r') as myfile:
            flat_file = myfile.read()
        s.read_string(flat_file)

        return flat_file, s

    def load_sx(self):
        flat, cfg = AuthConfig.load_sx_file(self.sx_file)

        self.sx_cfg = cfg

    def update_mtimes(self):
        self.user_file_mtime = os.stat(self.user_file).st_mtime
        self.key_file_mtime= os.stat(self.key_file).st_mtime

    def prepare(self, tenant_name="default", tenant_index=0, clear_shm=None):

        # set tenant information
        self.tenant_name = tenant_name
        self.tenant_index = tenant_index
        self.log_file = "/var/log/smithproxy_bend.%s.log" % (tenant_name,)

        # setup logger
        self.set_logger(self.log_file)

        # set listening port
        self.bend_port = 64000 + int(tenant_index)

        self.set_filenames(self.tenant_name)

        self.load_key()
        self.load_users()
        self.load_sx()

        self.update_mtimes()


class AuthManager(AuthConfig):

    def __init__(self):
        super(AuthManager, self).__init__(None)

        self.logon_shm = None
        self.logon6_shm = None
        self.token_shm = None
        self.last_refresh = time.time()
        self.clear_shm = False

        self.global_token_referer = {}
        self.server = None

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

        self.admin_manager = AdminManager(self.log)

    def prepare(self, tenant_name="default", tenant_index=0, clear_shm=None):
        super(AuthManager, self).prepare(tenant_name, tenant_index, clear_shm)

        self.server = SOAPpy.ThreadingSOAPServer(("localhost", self.bend_port))



    def setup_logon_tables(self, mem_name, mem_size, sem_name):

        self.logon_shm = LogonTable()
        self.logon_shm.setup(mem_name, mem_size, sem_name)

        if self.clear_shm:
            self.logon_shm.clear()
            self.logon_shm.write_header()

    def setup_logon_tables6(self, mem_name, mem_size, sem_name):

        self.logon6_shm = LogonTable(6)
        self.logon6_shm.setup(mem_name, mem_size, sem_name)

        if self.clear_shm:
            self.logon6_shm.clear()
            self.logon6_shm.write_header()

    def setup_token_tables(self, mem_name, mem_size, sem_name):

        self.token_shm = TokenTable()
        self.token_shm.setup(mem_name, mem_size, sem_name)

        if self.clear_shm:
            self.token_shm.clear()

        # test data
        # self.token_shm.seek(0)
        # self.token_shm.write(struct.pack('III', 1, 1, 576))
        # test1_token = "233474357"
        # test1_url = "idnes.cz"
        # self.token_shm.write(struct.pack('64s512s', test1_token, test1_url))

    def cleanup(self):

        self.token_shm.cleanup()
        self.logon_shm.cleanup()
        self.logon6_shm.cleanup()

    def token_data(self, token):

        self.log.debug("token_data: start, acquiring semaphore")

        self.token_shm.acquire()
        self.log.debug("token_data: start, semaphore acquired, loading..")
        self.token_shm.load()
        self.log.debug("token_data: start, token  table loaded")
        self.token_shm.release()
        self.log.debug("token_data: start, semaphore released")

        # print(str(self.token_shm.tokens.keys()))

        # some pretty-printing
        if token in self.token_shm.tokens.keys():
            if token in self.token_shm.used_tokens:
                self.log.warning("token " + token + " already used")
            else:
                self.log.debug("token " + token + " found")
        else:
            self.log.debug("token " + token + " not found ...")

        # say farewell
        if token in self.token_shm.used_tokens:
            return None

        # hit - send a link and invalidate
        if token in self.token_shm.tokens.keys():
            res = self.token_shm.tokens[token]
            self.token_shm.toggle_used(token)  # now is token already invalidated, and MAY be deleted
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

    def refresh(self):
        now = time.time()
        if now > self.last_refresh + 5:
            self.log.debug("refreshing logon list")
            self.logon_shm.acquire()
            self.logon_shm.load()  # load new data!
            self.logon_shm.release()

            self.token_shm.acquire()
            self.token_shm.load()  # load new data!
            self.token_shm.release()

            self.last_refresh = now

    def whois(self, ip):

        self.refresh()

        if ip in self.logon_shm.logons.keys():
            ret = self.logon_shm.logons[ip]
            self.log.debug("whois request for IP %s: %s " % (ip, str(ret)))
            return ret

        return []

    def deauthenticate(self, ip):
        self.log.info("deauthenticate request for IP %s " % (ip,))
        self.logon_shm.acquire()
        self.logon_shm.load()  # load new data!
        self.logon_shm.rem(ip)
        self.logon_shm.release()

    def authenticate_check(self, ip, username, password, identities):

        if ip not in self.address_identities.keys():
            self.address_identities[ip] = []

        ret = 0

        for i in identities:
            self.log.info("authenticate_check: matching against identity %s " % (i,))
            if i in self.identities_db.keys():
                ii = self.identities_db[i]

                for g in ii["groups"]:
                    self.log.debug("authenticate_check: checking group %s" % (g,))

                    exploded_members = unique_list(self.recursive_group_members(g))
                    self.log.debug("authenticate_check: full member list of %s: %s" % (g, str(exploded_members)))

                    for m in exploded_members:
                        self.log.debug("authenticate_check: investigating member target %s" % (m,))

                        source = ''
                        user = ''
                        group = ''
                        is_user = False

                        if m.find(':') >= 0:
                            is_user = True

                        self.log.debug("authenticate_check: investigating member target %s: user" % (m,))

                        if is_user:
                            pairlet = m.split(":")
                            source = pairlet[0]
                            user = pairlet[1]

                        elif m.find('@') >= 0:
                            pairlet = m.split("@")
                            source = pairlet[0]
                            group = pairlet[1]

                        if is_user and user != username:
                            self.log.debug("authenticate_check: investigating member target %s: user doesn't match" % (m,))
                            continue
                        else:
                            self.log.debug("authenticate_check: investigating member target %s: user matches" % (m,))

                            cur_ret = 0

                            if is_user:
                                cur_ret = self.authenticate_check_local(ip, username, password, identities)
                                ret += cur_ret
                            else:
                                cur_ret = self.authenticate_check_ldap(ip, username, password, identities, m)
                                ret += cur_ret

                            if cur_ret > 0:
                                self.log.info(
                                    "authenticate_check: user %s authenticated in element %s in %s" % (username, m, i))
                                # ret += 1
                                if i not in self.address_identities[ip]:
                                    self.address_identities[ip].append(i)

                                self.log.debug(
                                    "authenticate_check: checking member target %s: looking for other identities" % (
                                    m,))
                                if m in self.objects_identities.keys():
                                    for alt_identity in self.objects_identities[m]:
                                        if alt_identity not in self.address_identities[ip]:
                                            self.log.debug(
                                                "authenticate_check: checking member target %s: alt. identity: %s" % (
                                                m, alt_identity))
                                            self.address_identities[ip].append(alt_identity)
                                            ret += 1
                            else:
                                self.log.debug(
                                    "authenticate_check: investigating member target %s: authentication failed!" % (m,))

        if ret > 0:
            return ret

        # this is just for debug purposes.
        # if self.authenticate_check_local(ip,username,password,identities):
        #    self.log.info("authenticate_check: user " + username + " local auth successful from " + ip + " -- fallback authentication")
        #    self.address_identities[ip] = []
        #    return 1

        # reset authentication on failure
        self.address_identities[ip] = []
        return 0

    def authenticate(self, ip, username, password, token):

        self.log.info("authenticate: request: user %s from %s - token %s" % (username, ip, str(token)))

        ip_version = address_version(ip)
        self.log.debug("ip version: %d" % ip_version)

        ip_shm_table = None

        if ip_version == 4:
            ip_shm_table = self.logon_shm
        elif ip_version == 6:
            ip_shm_table = self.logon6_shm

        ret = False

        # make identities as broad as possible. This is safest default, identities are later narrowed down by token data
        identities = self.identities_db.keys()

        self.log.debug("acquiring token shm - %s" % (self.token_shm.memory_name,))
        try:
            self.log.debug("Last seen token table version: %d, rowsize: %d" % (self.token_shm.version, self.token_shm.row_size))

            self.token_shm.acquire()
            self.token_shm.load(forced=True)
            self.token_shm.release()

            self.log.debug("Token table version: %d" % (self.token_shm.version,))

        except Exception as e:
            self.log.error("error loading token shm: " + str(e))
        self.log.debug("released token shm")

        if token in self.token_shm.tokens.keys():
            res = self.token_shm.tokens[token]
            self.log.debug("authenticate: token data: " + str(res))

            token_data = res.split(" |")
            if len(token_data) > 1:
                identities = token_data[1:]
                self.log.debug("authenticate: token specific identities: " + str(identities))

        else:
            self.log.warning("authenticate: token data not received")

        self.log.info("authenticate: request for user %s from %s - against identities %s" % (username, ip, str(identities)))

        if not username:
            username = '<guest>'

        if self.authenticate_check(ip, username, password, identities) > 0:
            self.log.info("authenticate: user " + username + " auth successful from " + ip)

            # normalize identities
            identities_to_send = username
            if ip in self.address_identities.keys():
                x = self.address_identities[ip]
                if len(x) > 0:
                    for i in x:
                        identities_to_send += "+"
                        identities_to_send += i

            ip_shm_table.acquire()
            ip_shm_table.load()  # load new data!
            ip_shm_table.add(ip, username, identities_to_send)
            ip_shm_table.save(True)
            ip_shm_table.release()

            # :-D
            ret = True
            if token:
                # we have some token from www form

                if token in self.global_token_referer.keys():
                    ref = self.global_token_referer[token]
                    self.log.debug("token " + token + " global referer: " + ref)
                    return True, ref
                else:
                    return True, "/authenticated.html"
            else:
                # we dont have any token from www form
                return True, "/authenticated.html"

        else:
            self.log.warning("authenticate: user " + username + " auth failed from " + ip)

            if token in self.global_token_referer.keys():
                ref = self.global_token_referer[token]
                self.log.debug("token " + token + " global referer: " + ref)
                return False, "/cgi-bin/auth.py?token=%s" % (token)
            else:
                return False, "/cgi-bin/auth.py?token=0"

    def save_referer(self, token, ref):
        self.log.debug("incoming referer: " + token + " -> " + ref)

        self.global_token_referer[token] = ref

    def test_internal(self):
        #self.log.debug("test routine executed")

        #self.log.debug("backend file mtime check")
        u = os.stat(self.user_file).st_mtime
        k = os.stat(self.key_file).st_mtime

        # self.log.debug("%s: %s" % (self.user_file, str(u)))
        # self.log.debug("%s: %s" % (self.key_file, str(k)))

        if self.user_file_mtime != u or self.key_file_mtime!= k:
            self.log.warning("files have been modified, restart")

            if self.server:
                # don't clear shared memory on restart!
                self.clear_shm = False
                self.server.shutdown()

    def serve_forever(self):

        if self.server:
            self.log.info("Launching portal on " + self.portal_address + ":" + str(self.portal_port))
            self.server.registerFunction(self.authenticate)
            self.server.registerFunction(self.deauthenticate)
            self.server.registerFunction(self.save_referer)
            self.server.registerFunction(self.whois)

            self.server.registerFunction(self.admin_login)
            self.server.registerFunction(self.admin_token_list)
            self.server.registerFunction(self.admin_keepalive)
            self.server.registerFunction(self.admin_logout)

            self.server.registerFunction(self.test_internal)

            self.server.serve_forever()
        else:
            self.log.error("Server not initialized.")

    def load_config_users(self, user_items):
        for user in user_items:
            self.log.debug("user: " + user[0])
            # print user[1].items()

            d = {}
            d["type"] = "static"
            d["username"] = user[0]
            for pair in user[1].items():
                d[pair[0]] = pair[1]

            self.user_db[user[0]] = d
            self.log.debug("user: " + user[0] + " -> " + str(d))

    def load_config_groups(self, groups_items):
        self.log.debug("groups: ")
        for i in groups_items:
            d = {}
            d["name"] = i[0]
            self.log.debug("groups: " + i[0])

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
                            self.log.debug("groups: member %s is an user %s in source %s" % (gii, user, source))

                            if source in self.sources_db.keys() or source == "local":
                                self.log.debug("groups: member %s source %s check OK" % (gii, source))
                                d["members"].append(str(gii))
                            else:
                                self.log.error("groups: member %s source %s check not OK, invalidated" % (gii, source))

                        else:
                            pairlet = gii.split("@")
                            if len(pairlet) > 1:
                                group = pairlet[1]
                                source = pairlet[0]
                                self.log.debug("groups: member %s is a group %s in source %s" % (gii, group, source))

                                if source in self.sources_db.keys() or source == "local":
                                    self.log.debug("groups: member %s source %s check OK" % (gii, source))
                                    d["members"].append(str(gii))

                                    # groups require special care. Since we have flat authentication scheme,
                                    # we need to gather all groups which we are interested in for each source
                                    # this is because user can get authed with policy requiring membership in "group_A"
                                    # but later user hits policy which requires membership in "group_B".
                                    # we have to query all groups at once to avoid unnecessary authentication popups.

                                    if group not in self.sources_groups[source]:
                                        self.sources_groups[source].append(group)

                                else:
                                    self.log.error("groups: member %s source %s check not OK, invalidated" % (gii, source))

                else:

                    d[pair[0]] = pair[1]

                self.log.debug("groups: " + i[0] + " -> " + str(d))

            self.group_db[i[0]] = d

        for s in self.sources_groups.keys():
            self.log.debug("Interesting groups in source %s: %s" % (s, str(self.sources_groups[s])))

    def load_config_identities(self, identities_items):
        self.log.debug("identities: ")

        for i in identities_items:

            d = {}
            d["name"] = i[0]
            self.log.debug("identities: " + i[0])

            for pair in i[1].items():

                if pair[0] == "groups":
                    if "groups" not in d.keys():
                        d["groups"] = []

                    for gi in pair[1]:
                        if str(gi) in self.group_db.keys():
                            self.log.debug("identities: referenced group %s in database." % str(gi))
                            d["groups"].append(str(gi))

                            # dereference groups and fill all objects -> identities  
                            # so single object can be identified as member of more identities at once

                            members = unique_list(self.recursive_group_members(gi))
                            for m in members:
                                if m not in self.objects_identities.keys():
                                    self.objects_identities[m] = []

                                self.objects_identities[m].append(i[0])


                        else:
                            self.log.debug("identities: referenced group %s NOT in database." % str(gi))

                else:
                    d[pair[0]] = pair[1]

            self.log.debug("identities: " + i[0] + " -> " + str(d))
            self.identities_db[i[0]] = d

        self.log.debug("identities: dereferenced objects -> identities: " + str(self.objects_identities))

    def load_config_sources(self, sources_items):
        for si in sources_items:
            source_type = si[0]
            self.log.debug("sources: type %s" % (source_type,))

            for sii in si[1].items():
                self.log.debug("sources: %s (%s)" % (sii[0], source_type,))
                name = sii[0]
                body = sii[1]
                body = cfg_to_dict(body)
                self.sources_db[name] = body

                # add this source to interesting groups structure
                self.sources_groups[name] = []

                self.log.debug("sources: %s (%s) -> %s" % (name, source_type, str(body)))

                if source_type == "ldap":
                    self.sources_ldap_db[name] = body
                elif source_type == "local":
                    self.sources_local_db[name] = body

    def authenticate_check_local(self, ip, username, password, identities):

        try:
            if username in self.user_db:
                if "type" in self.user_db[username]:
                    if self.user_db[username]["type"] == "static":
                        if "password" in self.user_db[username]:
                            if self.user_db[username]['password'] == password:
                                return True
                        else:
                            if "encrypted_password" in self.user_db[username]:
                                if self.authenticate_local_decrypt(
                                        self.user_db[username]['encrypted_password']) == password:
                                    return True

        except KeyError as e:
            pass
        except IndexError as e:
            pass

        return False

    def authenticate_check_ldap(self, ip, username, password, identities, target):

        self.log.debug("authenticate_check_ldap: result: start")

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
            self.log.debug("authenticate: LDAP: searching for user'%s' in '%s'" % (username, target))
            user_dn, group_list = l.authenticate_user(username, password)
            if user_dn:
                self.log.debug("authenticate: LDAP: found user'%s' in '%s': DN=%s, GROUPS=%s" % (
                username, target, user_dn, str(group_list)))
            else:
                self.log.error("authenticate: LDAP: unable to find user'%s' in '%s'" % (username, target))

        else:
            self.log.error("authenticate: LDAP: unable to bind to search for user'%s' in '%s'" % (username, target))

        self.log.debug("authenticate_check_ldap: result: %s:%s" % (str(user_dn), str(group_list)))

        if user_dn:
            return True

        return False

    def admin_login(self, username, password, ip):
        return self.admin_manager.issue_token(username, ip)

    def admin_token_list(self, admin_token):
        if self.admin_manager.use_token(admin_token):
            return json.dumps(self.admin_manager.admin_tokens)

        return None

    def admin_keepalive(self, token):
        return self.admin_manager.use_token(token)

    def admin_logout(self, token):
        return self.admin_manager.remove_token(token)

    def admin_get_config(self, token):
        if self.admin_manager.use_token():
            return json.dumps()

    def init_data(self, clear_shm=None):
        self.portal_address = self.sx_cfg.settings.auth_portal.address
        self.portal_port = str(int(self.sx_cfg.settings.auth_portal.http_port) + int(self.tenant_index))
        self.log.setLevel(cfgloglevel_to_py(self.sx_cfg.settings.log_level))

        self.log.debug("loading config file")

        try:
            self.load_config_sources(self.user_cfg.sources.items())
            self.load_config_users(self.user_cfg.users.items())
            self.load_config_groups(self.user_cfg.groups.items())
            self.load_config_identities(self.user_cfg.identities.items())

        except Exception as e:

            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.log.error("Error loading config: %s" % (str(e),))
            self.log.error("Error loading config: %s" % (repr(traceback.format_tb(exc_traceback)),))


        # toggle one-time clearing tables
        if clear_shm:
            self.clear_shm = True

        if not self.logon_shm or clear_shm:
            self.setup_logon_tables("/smithproxy_auth_ok_%s" % (self.tenant_name,), 1024 * 1024,
                                "/smithproxy_auth_ok_%s.sem" % (self.tenant_name,))

        if not self.logon6_shm or clear_shm:
            self.setup_logon_tables6("/smithproxy_auth6_ok_%s" % (self.tenant_name,), 1024 * 1024,
                                 "/smithproxy_auth6_ok_%s.sem" % (self.tenant_name,))

        if not self.token_shm or clear_shm:
            self.setup_token_tables("/smithproxy_auth_token_%s" % (self.tenant_name,), 1024 * 1024,
                                "/smithproxy_auth_token_%s.sem" % (self.tenant_name,))

        if clear_shm:
            self.clear_shm = False


    def run(self, clear_shm=None):

        self.init_data(clear_shm)
        self.serve_forever()
        self.log.info("serve_forever finished.")



class TesterThread(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.port = port

    def run(self):
        bend = SOAPpy.SOAPProxy("http://127.0.0.1:%s" % (str(self.port),))

        while True:
            time.sleep(5)
            bend.test_internal()


def run_bend(tenant_name="default", tenant_index=0, clear_shm=None):

    first_start = True
    a = AuthManager()

    while True:
        a.prepare(tenant_name, tenant_index, first_start)
        a.log.info("starting main loop")
        if first_start:
            t = TesterThread(a.bend_port)
            t.setDaemon(True)
            t.start()

        first_start = False
        a.run(first_start)



if __name__ == "__main__":
    try:
        run_bend()
    except KeyboardInterrupt as e:
        print "Ctrl-C pressed."


