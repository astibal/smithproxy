#!/usr/bin/env python3
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

import argparse
import sys
import time
from pprint import pprint
import logging

title = """
    Smithproxy software - Accessory tools
"""

copyleft = """Copyleft by Ales Stibal <astib@mag0.net>"""



sys.path.append('/usr/share/smithproxy/infra/bend')
sys.path.append('/usr/share/smithproxy/infra/sslca')

from bend import AuthManager

def main():

    parser = argparse.ArgumentParser(
        description=title,
        epilog=" - %s " % (copyleft,))
    ts = parser.add_argument_group("Tenant info")
    ts.add_argument('--tenant-name', nargs=1, help='tenant name')

    ac = parser.add_argument_group("Actions")
    group1 = ac.add_mutually_exclusive_group()
    group1.add_argument('--inspect', action='store_true', help='dump users configuration')
    group1.add_argument('--user', nargs=1, help='user related actions')

    ac.add_argument('--password', nargs='?', default=None, help='change password. if empty, read from input')

    group2 = ac.add_mutually_exclusive_group()
    group2.add_argument('--check', action='store_true', help='check password')
    # add some day
    # group2.add_argument('--create', action='store_true', help='create a new user')


    args = parser.parse_args(sys.argv[1:])

    if not args.tenant_name:
        tenant_name = "default"
    else:
        tenant_name = args.tenant_name[0]

    a = AuthManager()
    a.log.setLevel(logging.FATAL)
    a.set_filenames(tenant_name=tenant_name)
    a.load_key()
    a.load_users()
    a.load_sx()
    a.init_data()

    if args.inspect:
        pprint(a.user_cfg)
    elif args.user:
        username = args.user[0]

        user_cx = a.user_cfg.lookup('users.' + username)

        if user_cx:
            a.log.info("switching context to user %s" % (username,))

            if not args.password:
                import getpass

                p1 = getpass.getpass()
                if not args.check:
                    p2 = getpass.getpass("Retype new password: ")

                    if p1 == p2:
                        args.password = p1
                    else:
                        print("Error, passwords don't match.")
                        sys.exit(1)
                else:
                    args.password = p1

            if args.password:

                if args.check:
                    epw = bytearray(user_cx.encrypted_password, 'utf8')
                    pw = a.authenticate_local_decrypt(epw).decode('utf8')

                    time.sleep(1)
                    if pw == args.password:
                        print("password check OK")
                        sys.exit(0)
                    else:
                        print("password check failed")

                    sys.exit(1)

                # continue with saving the password

                new_pass = a.authenticate_local_encrypt(bytearray(args.password, 'utf8'))

                # print("New password is: '%s'" % new_pass.decode('utf8'))

                user_cx.set('encrypted_password', new_pass.decode('utf8'))

                if new_pass:
                    if a.authenticate_local_decrypt(new_pass).decode('utf8') == args.password:
                        a.save_users()
                    else:
                        print("error: integrity check failed")

                        # below is just for debugging
                        # print("decrypted new password: '%s'" % a.authenticate_local_decrypt(new_pass).decode('utf8'))
                        # print("args.password: '%s'" % args.password)
            else:
                print("error: cannot set blank password")

        else:
            print("no such user :(")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print("")
        pass
