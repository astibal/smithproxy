#!/usr/bin/env python3

import os
import hashlib
import datetime
import socket
import ipaddress

import sxyca


def is_default_ca():
    fnm_cert = os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem")

    if os.path.isfile(fnm_cert):
        ff = ""
        with open(fnm_cert, 'r', encoding='utf-8') as f:
            ff = f.read()

        hh = hashlib.sha1(ff.encode('utf-8')).hexdigest()
        if hh == '5a8dacd191faf967a685091ae5732bd3806146a3':
            return True

    return False


def should_generate_cert(certname):
    fnm_cert = os.path.join(sxyca.SETTINGS["path"],certname)
    if os.path.isfile(fnm_cert):
        cert = sxyca.load_certificate(fnm_cert)
        expires = cert.not_valid_after

        delta = expires - datetime.datetime.now()

        if delta.days <= 0:
            print("    warning: certificate %s expires, or already expired" % (fnm_cert, ))
            return True

        elif delta.days <= 1:
            print("    warning: certificate %s expires tomorrow" % (fnm_cert, ))

        elif delta.days <= 7:
            print("    warning: certificate %s expires in %d days" % (fnm_cert, delta))

        print("    certificate %s valid." % (certname,))

        return False
    else:
        print("    cert file '%s'not found" % (fnm_cert, ))

    return True


# load smithproxy config and do the best to get FQDN where auth will be diverting traffic
def load_sans_from_config(configfile):

    sans = []
    ips = []

    try:
        import pylibconfig2 as cfg

        sxcfg = cfg.Config()
        sxcfg.read_file(configfile)

        portal_addr = None
        try:
            portal_addr = sxcfg.settings.auth_portal.address
            ipaddress.ip_address(portal_addr)
            print("   - cfg portal address is IP")
            ips.append(portal_addr)
        except ValueError:
            # ip is not recognized
            sans.append(portal_addr)
        except AttributeError:
            # config is not found
            pass

        portal_addr6 = None
        try:
            portal_addr6 = sxcfg.settings.auth_portal.address6
            ipaddress.ip_address(portal_addr6)
            print("   - cfg portal address6 is IP")
            ips.append(portal_addr6)
        except ValueError:
            # ip is not recognized
            sans.append(portal_addr6)
        except AttributeError:
            # config is not found
            pass

    except ImportError as e:
        print("   - w: cannot load pylibconfig2 - cannot specify exact portal FQDN")

    return [sans, ips]


def generate_portal_cert(ca_key, ca_cert):
    print("     - generating server certificate == ")

    portal_cn = None
    sans, ips = load_sans_from_config("/etc/smithproxy/smithproxy.cfg")

    portal_cn = socket.getfqdn()
    sans.append(portal_cn)

    try:
        from pyroute2 import IPRoute
        from pprint import pprint

        with IPRoute() as ipr:
            for intf in ipr.get_addr():
                for k,v in intf["attrs"]:
                    if k == "IFA_ADDRESS":
                        # don't add loopback addresses and auto-generated ones
                        if v != "::1" and not v.startswith("127.0.0") and not v.startswith("fe80:") \
                                    and not v.startswith("169.254"):
                            ips.append(v)

    except ImportError as e:
        print("     - w: cannot load pyroute2 - no IP addresses could be added to server cert")

    prt_key = sxyca.generate_rsa_key(2048)
    prt_csr = sxyca.generate_csr(prt_key, "prt", sans_dns=sans, sans_ip=ips, custom_subj={"cn": portal_cn})
    prt_cert = sxyca.sign_csr(ca_key, prt_csr, "prt", cacert=ca_cert)

    sxyca.save_key(prt_key, "portal-key.pem")
    sxyca.save_certificate(prt_cert, "portal-cert.pem")

    return prt_key, prt_cert


#
# @type: 'rsa' or 'ec'
# @key_size: size of RSA key (ignored for EC)
# @returns: (key, cert) tuple
#
def generate_ca(enctype='rsa', key_size=2048, custom_subject=None):
    print("     - generating new CA == ")

    if enctype != 'ec':
        # generate CA RSA key
        ca_key = sxyca.generate_rsa_key(key_size)
        sxyca.save_key(ca_key, "ca-key.pem", None)
    else:
        # generate CA RSA key
        ca_key = sxyca.generate_ec_key()
        sxyca.save_key(ca_key, "ca-key.pem", None)

    # generate CA CSR for self-signing & self-sign
    ca_csr = sxyca.generate_csr(ca_key, "ca", isca=True, custom_subj=custom_subject)
    ca_cert = sxyca.sign_csr(ca_key, ca_csr, "ca", isca=True)
    sxyca.save_certificate(ca_cert, "ca-cert.pem")

    return ca_key, ca_cert


def generate_server_cert(ca_key, ca_cert):
    print("     - generating server certificate == ")
    # generate default server key and certificate & sign by CA
    srv_key = sxyca.generate_rsa_key(2048)
    srv_csr = sxyca.generate_csr(srv_key, "srv")
    srv_cert = sxyca.sign_csr(ca_key, srv_csr, "srv", cacert=ca_cert)

    sxyca.save_key(srv_key, os.path.join(sxyca.SETTINGS["path"], "srv-key.pem"))
    sxyca.save_certificate(srv_cert, os.path.join(sxyca.SETTINGS["path"], "srv-cert.pem"))

    return srv_key, srv_cert


def ttl_filter(val):
    if ask_bot_filter_int(val):
        return 0 < int(val) <= 365


def check_certificates(etc_dir, assume_yes=True, dry_run=False, enforced=False):

    print("== Checking installed certificates ==")

    sxyca.init_directories(etc_dir)
    sxyca.init_settings(cn=None, c=None)
    sxyca.load_settings()

    def_ca = False
    gen_ca = False
    gen_srv = False
    gen_prt = False

    print("== Checking CA cert ==")

    if os.path.isfile(os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem")):
        if is_default_ca():

            def_ca = True
            print("   - Default CA delivered by packaging system has been detected.")

            if assume_yes:
                print("   - New CA will be generated.")
                gen_ca = True
            else:
                if ask_bot(["yes", "no"], "   ==> Do you want to generate your own CA?") == 'yes':
                    gen_ca = True

        # check only if previously not detected default ca and not responded with yes
        if not gen_ca:
            if should_generate_cert(os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem")):
                print("   - New CA must be generated (it's not valid anymore).")
                gen_ca = True

            elif enforced:
                print("   - New CA must be generated (enforced by user).")
                gen_ca = True

    else:
        print("   - doesn't exist, generating!")
        gen_ca = True


    ttl = 60

    if gen_ca:
        try:
            ttl = sxyca.SETTINGS["ttl"]
        except KeyError:
            print("   - w: ttl not set in config")

        ttl = ask_bot([ttl], "   ==> Lifetime in days", other_choices=True, other_value_filter=ttl_filter)
        print("   - i: using ttl %s" % ttl)

    print("== checking default server cert ==")
    file = os.path.join(sxyca.SETTINGS["path"], "srv-cert.pem")
    if os.path.isfile(file):
        if should_generate_cert(file) or gen_ca:
            reason = "(validity)"
            if gen_ca:
                reason = "(new CA)"

            print("   - New default server certificate will be generated " + reason )
            gen_srv = True
    else:
        print("   - doesn't exist, generating!")
        gen_srv = True

    print("== checking portal cert ==")

    ca_file = os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem")
    ca_cert_temp = None
    if os.path.isfile(ca_file):
        ca_cert_temp = sxyca.load_certificate(ca_file)

    file = os.path.join(sxyca.SETTINGS["path"], "portal-cert.pem")

    if ca_cert_temp and os.path.isfile(file):

        prt_cert = sxyca.load_certificate(file)

        if prt_cert.issuer == ca_cert_temp.subject:
            # if we control prt-cert, always generate new one!
            reason = "(always generating self-issued portal cert on start)"
            if gen_ca:
                reason = "(new CA)"

            if should_generate_cert(file):
                reason = "(validity)"

            print("   - New portal certificate will be generated " + reason)
            gen_prt = True

        else:
            print("   - 3rd party portal cert, keeping it!")

    else:
        print("   - doesn't exist, generating!")
        gen_prt = True


    new_ca = False

    print("\n== Execute ==\n")

    if not dry_run:
        if gen_ca:
            # new CA - all must be regenerated
            gen_srv = True
            gen_prt = True

            assy_type = None
            try:
                if "type" in sxyca.SETTINGS["ca"]["settings"]:
                    assy_type = sxyca.SETTINGS["ca"]["settings"]["type"]
            except KeyError:
                pass

            if not assy_type:
                assy_type = ask_bot(['rsa', 'ec'], "   ==> Which CA type you prefer?")

            print("\n   - New Certificate Authority:")
            ca_key, ca_cert = generate_ca(enctype=assy_type)
            if ca_key and ca_cert:
                print("   - GENERATED")
                new_ca = True
            else:
                print("   - E: failed")

        else:
            ca_key = sxyca.load_key(os.path.join(sxyca.SETTINGS["path"], "ca-key.pem"))
            ca_cert = sxyca.load_certificate(os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem"))
            print("\n   - Using CURRENT CA")

        if gen_srv:
            print("\n   - Server certificate:")
            srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
            if srv_key and srv_cert:
                print("   - GENERATED")
            else:
                print("   - E: failed")

        if gen_prt:
            print("\n   - Portal certificate:")
            prt_key, prt_cert = generate_portal_cert(ca_key, ca_cert)
            if prt_key and prt_cert:
                print("   - GENERATED")
            else:
                print("   - E: failed")


        print("\n== Finished ==\n")

        if new_ca:
            with open(os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem")) as f:
                c = f.read()
                print("   - !!! New CA certificate: ")
                print(c)
    else:
        print("   - dry mode: finished")


if __name__ == "__main__":
    import sys
    sys.path.append('/usr/share/smithproxy/infra/sslca')
    sys.path.append('/usr/share/smithproxy/infra/bend')

    from bendutil import ask_bot
    from bendutil import ask_bot_filter_int

    sxyca.Options.indent = 6

    sx_path = "/etc/smithproxy"

    if len(sys.argv) > 1:
        sx_path = sys.argv[1]

    dry_run = False

    try:
        while True:

            action = ask_bot(['No', 'Yes', 'Dry', 'Enforce'],
                 "Do you want to check and generate new certificates?\n"
                 "   - Note: you can modify attribute values in file: /etc/smithproxy/certs/default/sslca.json\n"
                 "   - ")

            a_dry_run = False
            a_enforce = False


            if action != 'No':

                if action == 'Dry':
                    a_dry_run = True

                if action == 'Enforce':
                    a_enforce = True

                check_certificates(sx_path, assume_yes=False, dry_run=a_dry_run, enforced=a_enforce)
            else:
                print("Ok, not touching CA at all.")

            print("...")

            if not a_dry_run:
                break
    except KeyboardInterrupt:
        print("\n\n\nCtrl-C: terminating")
