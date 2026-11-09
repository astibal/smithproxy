#!/usr/bin/env python3

# this script will only refresh portal certificates

import os
import sys

sys.path.append('/usr/share/smithproxy/infra/sslca')
sys.path.append('/usr/share/smithproxy/infra/bend')

import sxyca
import makecerts as utils
from cftarcerts import certificate_workspace


def portal_autogen():

    with certificate_workspace() as workspace:
        sxyca.init_directories(str(workspace.root))
        sxyca.init_settings(cn=None, c=None)
        sxyca.load_settings()

        ca_key = sxyca.load_key(os.path.join(sxyca.SETTINGS["path"], "ca-key.pem"))
        ca_cert = sxyca.load_certificate(os.path.join(sxyca.SETTINGS["path"], "ca-cert.pem"))

        prt_key, prt_cert = utils.generate_portal_cert(
            ca_key, ca_cert, str(workspace.config_file))

    print("portal certificate regenerated")

    return prt_key, prt_cert


if __name__ == "__main__":




    portal_autogen()
