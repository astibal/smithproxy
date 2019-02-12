from __future__ import print_function


import sys
import os
import re
import hashlib
import datetime
import socket
import ipaddress

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import sxyca


def is_default_ca():
    fnm_cert = os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem")

    if os.path.isfile(fnm_cert):
        ff = ""
        with open(fnm_cert,'r',encoding='utf-8') as f:
            ff = f.read()

        hh = hashlib.sha1(ff.encode('utf-8')).hexdigest()
        if hh == '7661696a2b46d4bfd39d96324a1b4619777bf988':
            print("default certificate!")
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
        print("    cert file '%s'not found"% (fnm_cert,))

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
            print("cfg portal address is IP")
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
            print("cfg portal address6 is IP")
            ips.append(portal_addr6)
        except ValueError:
            # ip is not recognized
            sans.append(portal_addr6)
        except AttributeError:
            # config is not found
            pass

    except ImportError as e:
        print("... cannot load pylibconfig2 - cannot specify exact portal FQDN")


    return [sans, ips]

def generate_portal_cert(ca_key,ca_cert):
    portal_cn = None
    sans, ips = load_sans_from_config("/tmp/etc/smithproxy/smithproxy.cfg")

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
        print("... cannot load pyroute2 - no IP addresses could be added to server cert")



    prt_key = sxyca.generate_rsa_key(2048)
    prt_csr = sxyca.generate_csr(prt_key, "prt",sans_dns=sans, sans_ip=ips, custom_subj = {"cn": portal_cn })
    prt_cert = sxyca.sign_csr(ca_key, prt_csr, "prt", valid=30, cacert=ca_cert)

    sxyca.save_key(prt_key, "portal-key.pem")
    sxyca.save_certificate(prt_cert, "portal-cert.pem")

    return prt_key, prt_cert


def generate_ca():
    # generate CA RSA key
    ca_key = sxyca.generate_rsa_key(2048)
    sxyca.save_key(ca_key, "ca-key.pem", None)

    # generate CA CSR for self-signing & self-sign
    ca_csr = sxyca.generate_csr(ca_key, "ca", isca=True)
    ca_cert = sxyca.sign_csr(ca_key, ca_csr, "ca", valid=2 * 30, isca=True)
    sxyca.save_certificate(ca_cert, "ca-cert.pem")

    return ca_key, ca_cert


def generate_server_cert(ca_key, ca_cert):
    # generate default server key and certificate & sign by CA
    srv_key = sxyca.generate_rsa_key(2048)
    srv_csr = sxyca.generate_csr(srv_key, "srv")
    srv_cert = sxyca.sign_csr(ca_key, srv_csr, "srv", valid=30, cacert=ca_cert)

    sxyca.save_key(srv_key, os.path.join(sxyca.SETTINGS["path"],"srv-key.pem"))
    sxyca.save_certificate(srv_cert, os.path.join(sxyca.SETTINGS["path"],"srv-cert.pem"))

    return srv_key, srv_cert


def check_certificates(etc_dir):

    sxyca.SETTINGS["path"] = etc_dir


    for X in [
        sxyca.SETTINGS["path"],
        os.path.join(sxyca.SETTINGS["path"],"certs/"),
        os.path.join(sxyca.SETTINGS["path"],"certs/","default/") ]:

        if not os.path.isdir(X):
            try:
                os.mkdir(X)
            except FileNotFoundError:
                print("fatal: path {} doesn't exit".format(X))
                return
            except PermissionError:
                print("fatal: Permission denied: {}".format(X))
                return



    sxyca.SETTINGS["path"] = os.path.join(sxyca.SETTINGS["path"], "certs/", "default/")
    sxyca._write_default_settings()
    sxyca.load_settings()


    gen_ca = False
    gen_srv = False
    gen_prt = False


    print("== checking CA cert ==")
    if os.path.isfile(os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem")):
        if is_default_ca():
            print("    Default CA delivered by packaging system has been detected.")
            print("    New CA will be generated.")
            gen_ca = True

        if should_generate_cert(os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem")):
            print("    New CA will be generated.")
            gen_ca = True

    else:
        print("    doesn't exist, generating!")
        gen_ca = True


    # TODO: following 3 blocks could be generalized
    print("== checking default server cert ==")
    file = os.path.join(sxyca.SETTINGS["path"],"srv-cert.pem")
    if os.path.isfile(file):
        if should_generate_cert(file) or gen_ca:
            print("    New default server will be generated.")
            gen_srv = True
    else:
        print("    doesn't exist, generating!")
        gen_srv = True


    print("== checking portal cert ==")
    file = os.path.join(sxyca.SETTINGS["path"],"portal-cert.pem")
    if os.path.isfile(file):
        if should_generate_cert(file) or gen_ca:
            print("    New portal certificate will be generated.")
            gen_prt = True

        prt_cert = sxyca.load_certificate(file)
        ca_cert_temp = sxyca.load_certificate(os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem"))

        #rint(ca_cert_temp.subject)
        #print(prt_cert.issuer)
        if prt_cert.issuer == ca_cert_temp.subject:
            # if we control prt-cert, always generate new one!
            print("    we hold portal cert, always generating a new one on start!")
            gen_prt = True
        else:
            print("    we haven't issued the cert, keeping it!")

    else:
        print("    doesn't exist, generating!")
        gen_prt = True


    ca_key = None
    ca_cert = None

    if gen_ca:
        # new CA - all must be regenerated
        gen_srv = True
        gen_prt = True

        print("generating a new CA")
        ca_key, ca_cert = generate_ca()

    else:
        ca_key = sxyca.load_key(os.path.join(sxyca.SETTINGS["path"],"ca-key.pem"))
        ca_cert = sxyca.load_certificate(os.path.join(sxyca.SETTINGS["path"],"ca-cert.pem"))
        print("using current CA")

    if gen_srv:
        srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)

    if gen_prt:
        prt_key, prt_cert = generate_portal_cert(ca_key, ca_cert)


if __name__ == "__main__":
    check_certificates("/tmp/etc/smithproxy")