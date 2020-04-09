#!/usr/bin/env python3

# this script will only refresh portal certificates

import os
import sys
import sxyca
import makecerts as utils


def portal_autogen():

    sxyca.init_directories("/etc/smithproxy")
    sxyca.init_settings(cn=None, c=None)
    sxyca.load_settings()

    ca_key = sxyca.load_key(os.path.join(sxyca.SETTINGS["path"], "ca-key.pem"))
    ca_cert = sxyca.load_certificate(os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem"))

    prt_key, prt_cert = utils.generate_portal_cert(ca_key, ca_cert)

    print("portal certificate regenerated")

    return prt_key, prt_cert


if __name__ == "__main__":


    sys.path.append('/usr/share/smithproxy/infra/sslca')
    sys.path.append('/usr/share/smithproxy/infra/bend')

    portal_autogen()