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

SALT_LEN = 24


def load_key_file(f):
    try:
        f = open(f, "r")
        a = f.read()
        f.close()

        return a

    except IOError as e:
        print("Error key file. Using filename as the passphrase.")
        return f


def gen_rand_bytes(l):
    import os
    return os.urandom(l)


def xor_bytearray(data, key, encode=False, decode=False) -> bytearray:
    from itertools import cycle
    import base64

    if decode:
        data = base64.b64decode(data)

    xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in
                    zip(data.decode('ascii', 'ignore'), cycle(key.decode('ascii', 'ignore'))))

    xored = bytearray(xored, 'utf8')

    if encode:
        xored = base64.b64encode(xored)

    return xored


def xor_encrypt(data, key) -> bytearray:
    return xor_bytearray(data, key, encode=True, decode=False)


def xor_decrypt(data, key) -> bytearray:
    return xor_bytearray(data, key, encode=False, decode=True)


def xor_salted_encrypt(data, key) -> bytearray:
    import base64
    salt = gen_rand_bytes(SALT_LEN)
    tmp_key = xor_bytearray(key, salt)

    return base64.b64encode(salt) + b"-" + xor_encrypt(data, tmp_key)


def xor_salted_decrypt(data, key) -> bytearray:

    r = data.split(b"-")

    if len(r) > 1:
        import base64
        b_salt = r[0]
        salt = base64.b64decode(b_salt)
        salt = xor_bytearray(key, salt)

        return xor_decrypt(r[1], salt)

    return bytearray([])


def aes_salted_encrypt(data, key) -> bytearray:
    import base64
    salt = gen_rand_bytes(SALT_LEN)

    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # do stuff
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=100000,
        backend=default_backend()
    )

    der_key = base64.urlsafe_b64encode(kdf.derive(key))
    f = Fernet(der_key)

    token = f.encrypt(bytes(data))

    return base64.b64encode(salt) + b"-" + base64.b64encode(token)


def aes_salted_decrypt(data, key) -> bytearray:

    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    r = data.split(b"-")

    if len(r) > 1:
        import base64
        b_salt = r[0]
        salt = base64.b64decode(b_salt)

        # do stuff
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(salt),
            iterations=100000,
            backend=default_backend()
            )

        der_key = base64.urlsafe_b64encode(kdf.derive(key))
        f = Fernet(der_key)

        txt = f.decrypt(base64.b64decode(r[1]))
        return txt


    return bytearray([])


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 3:
        if "-e" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print("")
            xor_encrypt(t, p)
        elif "-d" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print("")
            xor_decrypt(t, p)

        elif "-es" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print("")
            xor_salted_encrypt(t, p)
        elif "-ds" == sys.argv[1]:
            t = sys.argv[2]
            p = load_key_file(sys.argv[3])
            print("")
            xor_salted_decrypt(t, p)
