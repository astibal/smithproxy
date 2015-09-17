#!/usr/bin/env python

import ldap
import pprint
import logging
import sys
import time
import string

# Some favorite LDAP search queries. 
# $cnid -- attribute which represents logon name (openldap: uid, windows AD: sAMAccountName)
# $user -- enter username you would like to search.
LDAP_SEARCH_USER='(&(objectClass=person)(${cnid}=${user}))'

# Distinguishing names: used in CryptoCache as the recognition entry,
# which must be unique.
#

LDAP_MS_DSTN="sAMAccountName"
LDAP_UX_DSTN="uid"


# Some printinng useful for debugging, nothing more.
def pprint_result(r):
    username = ""
    for cn, atts in r: 
	if cn == None:
	    continue
        print "RESULT: %s" % cn
	for k in atts.keys():
	    print "\tAttribute \'%s\': %s" % (k,str(atts[k]))


# Used profile entries:
# crypto_atts: attributes which are known to be encrypted
# crypto_dstn: key used to distinguish between particular result queries. Usually kind of username 
#		attribute.
#
# network_timeout: how long we should wait until some response arrives
# bind_dn:  bind using some specific account
# bind_pw: bind_dn password
# bind_uri: URI for the connection


class LdapCon(object):

    # allow to create LdapCon without cryptocache
    def __init__(self):
	_ldapcon = None
	self.flushProfile()

    def __init__(self):
	_ldapcon = None
	self.flushProfile()

    @staticmethod
    def empty_profile():
        profile = {}
        profile["network_timeout"] = 1000
        profile["bind_dn"] = 'dc='
        profile["bind_pw"] = ''
        profile["bind_uri"] = ''
        profile["cnid"] = 'uid'
        
        return profile

    def flushProfile(self):
        self.profile = LdapCon.empty_profile()

    def updateProfile(self,u):
        self.profile.update(u)

    def init(self):
        self._ldapcon = None
        
        logging.debug("ldapcon.init:")
        
        if self.profile["bind_uri"] == '' and "ip" in self.profile.keys():
            self.profile["bind_uri"] = "ldap://" + self.profile["ip"]
            logging.debug("ldapcon.init: specifying uri using ip key")
            
            if "port" in self.profile:
                if self.profile["port"] != '' or not self.profile["port"]:
                    self.profile["bind_uri"]+=":"+str(self.profile["port"])

        logging.debug("ldapcon.init: uri: " + self.profile["bind_uri"])

        self._ldapcon = ldap.initialize(self.profile["bind_uri"])
        self.network_timeout = self.profile["network_timeout"]
        
        logging.debug("ldapcon.init: ok")
        
    def bind(self,custom_u=None,custom_p=None):
        
        logging.debug("ldapcon.bind:")
        u = self.profile["bind_dn"]
        p = self.profile["bind_pw"]
        
        if custom_u:
            u = custom_u
        if custom_p:
            p = custom_p
    
        #logging.debug("ldapcon.bind: about to bind with user '%s' and password '%s'" % (u,p)) # :->
        logging.debug("ldapcon.bind: about to bind with user '%s' " % (u,))
        
        r = self._ldapcon.bind(u,p)
        logging.debug("ldapcon.bind: bind result: '%s'" % (str(r),))
        
        #print "bind returns: %d" % r
        rr = self._ldapcon.whoami_s()
        logging.debug("ldapcon.bind: whoami test result '" + str(rr) + "'")
        #print "whoami returns: '%s'" % rr
        if rr == '':
            logging.info(self.profile["bind_uri"] + ": invalid credentials check for user '%s'" % (str(u),))
            r = ''
        
        logging.debug("ldapcon.bind: result: '%s'" % (str(r),))
        return r
    
    def raw_query(self, base, query, filter=None, scope=ldap.SCOPE_SUBTREE):
	r = self._ldapcon.search_s(base, scope, query, filter)
	nr = []

	for cn, atts in r:
	    dstn = None

	    if not cn:
		# We don't want to return LDAP Refferals. Skip it.
		continue
	    
	    nr.append((cn, atts ))
	
	return nr
	    

# Used profile entries:
#   user: user query string _template_ with $user variable (can be for example '*', or username)
#   base: LDAP base DN
#  scope: LDAP scope constant (see LDAP module docs)
# filter: list of attributes we are interested in

class LdapSearch(LdapCon):

    def __init__(self):
        LdapCon.__init__(self)
        self.profile = LdapSearch.empty_profile()

    @staticmethod
    def empty_profile():
        d = LdapCon.empty_profile()
        e = {}
        e["user"] = LDAP_SEARCH_USER
        e["base_dn"] = ""
        e["filter"] = []
        e["scope"] = ldap.SCOPE_SUBTREE
        e["recursive_member_attr"] = "uniqueMember"
        
        d.update(e)
        
        return d

        

    def search_user_dn(self, username, query_dict=None):
        r = None
        logging.debug("ldapsearch.search_user_dn: ")
        try:
            logging.debug("ldapsearch.search_user_dn: using template: " + self.profile["user"])
            template = string.Template(self.profile["user"])
            
            q = template.substitute(cnid=self.profile["cnid"],user=username) 
            logging.debug("ldapsearch.search_user_dn: query: " + q)
            #print "DEBUG: searchUser query=\'%s\'" % q

            r = self.raw_query(self.profile["base_dn"], q, 
                                self.profile["filter"],
                                self.profile["scope"])
            logging.debug("ldapsearch.search_user_dn: query result: " + str(r))
        except ldap.error,e:
            logging.debug("ldapsearch.search_user_dn: query exception caught: " + str(e))
        except KeyError,e:
            logging.debug("ldapsearch.search_user_dn: query exception caught: " + str(e))

        logging.debug("ldapsearch.search_user_dn: returning %d objects" % (len(r),))
        return r

    def authenticate_user(self,username,password,lookup_only=False):
        logging.debug("ldapsearch.authenticate_user: FIND")
        r = self.search_user_dn(username)
        if r:
            logging.debug("ldapsearch.authenticate_user: BIND")
            self.init()
            res = self.bind(r[0][0],password)
            #print "Authenticate: %d" % res
            if res == '' and not lookup_only:
                logging.debug("ldapsearch.authenticate_user: FAILED")
                return (None,None)
            
            logging.debug("ldapsearch.authenticate_user: GROUPS")
            groups = self.groups_user_dn(r[0][0])
            logging.debug("ldapsearch.authenticate_user: %d group(s) found" % (len(groups),))
            
            return (r[0][0],groups)
        
        logging.debug("ldapsearch.authenticate_user: NOT FOUND")
        return (None,None)
    
    def groups_user_dn(self,user_dn):
        ret = []
        
        self.init()
        res = self.raw_query(self.profile["base_dn"],"%s=%s" % (self.profile["recursive_member_attr"],user_dn))
        if res:
            for r in res:
                ret.append(r[0])
        
        return ret
        

    # test cases, examples


# ldapsearch -h 192.168.254.1 -x -b dc=nodomain -D cn=admin,dc=nodomain -w smithproxy 'uid=astib'
# ldapsearch -h 192.168.254.1 -x -b dc=nodomain -D cn=admin,dc=nodomain -w smithproxy 'uniqueMember=cn=Ales Stibal,cn=users,dc=nodomain

def test_LdapSearch(ip):
    myldap = LdapSearch()
    myldap.profile["bind_uri"] += ip
    myldap.profile["bind_dn"] = 'cn=admin,dc=nodomain'
    myldap.profile["bind_pw"] = 'smithproxy'
    myldap.profile["base_dn"] = 'dc=nodomain'
    myldap.profile["filter"] = ['uid','info','mobile','email','memberOf']

    try:
        myldap.init()
        myldap.bind()
        dn = myldap.search_user_dn('astib')
        if dn:
            print "DN found: " + dn[0][0]
        
        myldap.init()
        r = myldap.authenticate_user('astib','smithproxy')
        if r:
            rr = myldap.groups_user_dn(r)
            print rr

    except ldap.LDAPError, e:
        print "LDAP ERROR: %s" % str(e)
    else:
        print "OK: All LDAP operations returned sucessfully."

    # print out whole profile
    # pprint.pprint(myldap.profile)



if __name__ == "__main__":

    test_LdapSearch(sys.argv[1])
