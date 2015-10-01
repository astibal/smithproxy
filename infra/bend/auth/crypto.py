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


SALT_LEN=24

def load_key_file(f):
    try:
        f = open(f,"r")
        a = f.read()
        return a
        f.close()    
    except IOError, e:
        print "Error key file. Using filename as the passphrase."
        return f
    

def gen_rand_bytes(l):
    import os
    return os.urandom(l)

def xor_crypt_string(data, key, encode=False, decode=False):
    from itertools import izip, cycle
    import base64
    if decode:
        data = base64.b64decode(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.b64encode(xored).strip()
    return xored


def xor_encrypt(data,key):
    return xor_crypt_string(data,key,encode=True,decode=False)

def xor_decrypt(data,key):
    return xor_crypt_string(data,key,encode=False,decode=True)
    
def xor_salted_encrypt(data,key):
    import base64
    salt = gen_rand_bytes(SALT_LEN) 
    #print "salt: " + salt
    tmp_key = xor_crypt_string(key,salt)
    #print "tmp_key: " + tmp_key
    
    return base64.encodestring(salt).strip()+"-"+xor_encrypt(data,tmp_key)

def xor_salted_decrypt(data,key):
    r = data.split("-")
    if len(r) > 1:
        import base64
        salt = base64.decodestring(r[0]).strip()
        return xor_decrypt(r[1],xor_crypt_string(key,salt))
        
    return None

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 3:
        if "-e" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print xor_encrypt(t,p)
        elif "-d" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print xor_decrypt(t,p)
            
        elif "-es" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print xor_salted_encrypt(t,p)
        elif "-ds" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print xor_salted_decrypt(t,p)            
            