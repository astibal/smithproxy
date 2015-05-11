#!/usr/bin/env python

import ldap, pprint
import sys, time, string

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
# bind_pwd: bind_dn password
# bind_uri: URI for the connection


class LdapCon(object):

    # allow to create LdapCon without cryptocache
    def __init__(self):
	_ldapcon = None
	self.flushProfile()

    def __init__(self):
	_ldapcon = None
	self.flushProfile()

    def flushProfile(self):
	self.profile = {}
	self.profile["network_timeout"] = 1000
	self.profile["bind_dn"] = 'dc='
	self.profile["bind_pwd"] = ''
	self.profile["bind_uri"] = 'ldap://'
	self.profile["cnid"] = 'uid'

    def init(self):
        self._ldapcon = None
        self._ldapcon = ldap.initialize(self.profile["bind_uri"])
        self.network_timeout = self.profile["network_timeout"]
        
    def bind(self,custom_u=None,custom_p=None):
        u = self.profile["bind_dn"]
        p = self.profile["bind_pwd"]
        
        if custom_u:
            u = custom_u
        if custom_p:
            p = custom_p
    
        #print "bind:"
        #print u
        #print p
        r = self._ldapcon.bind(u,p)
        #print "bind returns: %d" % r
        rr = self._ldapcon.whoami_s()
        #print "whoami returns: '%s'" % rr
        if rr == '':
            print "WARNING: invalid credentials!"
        
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
        self.profile["user"] = LDAP_SEARCH_USER
        self.profile["base"] = ""
        self.profile["filter"] = []
        self.profile["scope"] = ldap.SCOPE_SUBTREE
        self.profile["recursive_member_attr"] = "uniqueMember"

    def search_user_dn(self, username, query_dict=None):
        template = string.Template(self.profile["user"])

        q = template.substitute(cnid=self.profile["cnid"],user=username) 
        #print "DEBUG: searchUser query=\'%s\'" % q

        r = self.raw_query(self.profile["base"], q, 
                            self.profile["filter"],
                            self.profile["scope"])

        return r

    def authenticate_user(self,username,password):
        r = self.search_user_dn(username)
        if r:
            self.init()
            res = self.bind(r[0][0],password)
            #print "Authenticate: %d" % res
            if res == '':
                #print "Authentication failed!"
                return None
            
            return r[0][0]
            
        return None
    
    def groups_user_dn(self,user_dn):
        ret = []
        
        self.init()
        res = self.raw_query(self.profile["base"],"%s=%s" % (self.profile["recursive_member_attr"],user_dn))
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
    myldap.profile["bind_pwd"] = 'smithproxy'
    myldap.profile["base"] = 'dc=nodomain'
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
