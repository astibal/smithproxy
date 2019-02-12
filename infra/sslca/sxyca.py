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
from __future__ import print_function

import datetime
import json
import os

import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import AuthorityInformationAccessOID
SETTINGS = {
    "ca": {},
    "srv": {},
    "clt": {},
    "prt": {},
    "path": "/tmp/"
}


def _write_default_settings():
    global SETTINGS

    # we want to extend, but not overwrite already existing settings
    load_settings()

    r = SETTINGS

    for k in ["ca", "srv", "clt", "prt"]:
        if k not in r:
            r[k] = {}

    for k in ["ca", "srv", "clt", "prt"]:
        if "ou" not in r[k]: r[k]["ou"] = None
        if "o" not in r[k]:  r[k]["o"] = "Smithproxy Software"
        if "s" not in r[k]:  r[k]["s"] = None
        if "l" not in r[k]:  r[k]["l"] = None
        if "c" not in r[k]:  r[k]["c"] = "CZ"

    if "cn" not in r["ca"]:  r["ca"]["cn"] = "Smithproxy Root CA"
    if "cn" not in r["srv"]:  r["srv"]["cn"] = "Smithproxy Server Certificate"
    if "cn" not in r["clt"]:  r["clt"]["cn"] = "Smithproxy Client Certificate"
    if "cn" not in r["prt"]:  r["prt"]["cn"] = "Smithproxy Portal Certificate"


    if "settings" not in r["ca"]: r["ca"]["settings"] = {
        "grant_ca": "false"
    }


    # print("config to be written: %s" % (r,))

    try:
        with open(os.path.join(SETTINGS["path"], "sslca.json"), "w") as f:
            json.dump(r, f, indent=4)

    except Exception as e:
        print("write_default_settings: exception caught: " + str(e))


def load_settings():
    global SETTINGS
    try:
        with open(os.path.join(SETTINGS["path"], "sslca.json"), "r") as f:
            r = json.load(f)
            # print("load_settings: loaded settings: {}", str(r))

            SETTINGS = r

    except Exception as e:
        print("load_default_settings: exception caught: " + str(e))


def generate_rsa_key(size):
    return rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())

def load_key(fnm, pwd=None):
    with open(fnm, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(),password=pwd, backend=default_backend())



def generate_ec_key(curve):
    return ec.generate_private_key(curve=curve, backend=default_backend())


def save_key(key, keyfile, passphrase=None):

    #inner function
    def choose_enc(pwd):
        if not pwd:
            return serialization.NoEncryption()
        return serialization.BestAvailableEncryption(pwd)

    try:
        with open(os.path.join(SETTINGS['path'], keyfile), "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=choose_enc(passphrase),
            ))

    except Exception as e:
        print("save_key: exception caught: " + str(e))


NameOIDMap = {
    "cn": NameOID.COMMON_NAME,
    "ou": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "o": NameOID.ORGANIZATION_NAME,
    "l": NameOID.LOCALITY_NAME,
    "s": NameOID.STATE_OR_PROVINCE_NAME,
    "c": NameOID.COUNTRY_NAME
}

def construct_sn(profile, override={}):
    snlist = []

    for subj_entry in ["cn", "ou", "o", "l", "s", "c"]:
        if  subj_entry in override and subj_entry in NameOIDMap:
            snlist.append(x509.NameAttribute(NameOIDMap[subj_entry], override[subj_entry]))

        elif subj_entry in SETTINGS[profile] and SETTINGS[profile][subj_entry] and subj_entry in NameOIDMap:
            snlist.append(x509.NameAttribute(NameOIDMap[subj_entry], SETTINGS[profile][subj_entry]))

    return snlist


def generate_csr(key, profile, sans_dns=None, sans_ip=None, isca=False, custom_subj={}):
    global SETTINGS

    sn = x509.Name(construct_sn(profile, custom_subj))

    sans_list = []

    if sans_dns:
        for s in sans_dns:
            sans_list.append(x509.DNSName(s))

    if sans_ip:
        for i in sans_ip:
            ii = ipaddress.ip_address(i)
            sans_list.append(x509.IPAddress(ii))


    sans = x509.SubjectAlternativeName(sans_list)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(sn)

    if sans:
        builder = builder.add_extension(sans, critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=isca, path_length=None), critical=True)

    csr = builder.sign(key, hashes.SHA256(), default_backend())

    return csr


def sign_csr(key, csr, caprofile, valid=30, isca=False, cacert=None, aia_issuers=None,ocsp_responders=None):
    global SETTINGS

    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)

    if not cacert:
        builder = builder.issuer_name(x509.Name(construct_sn(caprofile)))
    else:
        builder = builder.issuer_name(cacert.subject)

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * valid))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(csr.public_key())

    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)

    # more info about issuer

    has_ski = False
    try:
        if cacert:
            ski = cacert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                                            critical=False)
            has_ski = True
    except x509.extensions.ExtensionNotFound:
        has_ski = False

    if not has_ski:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                                        critical=False)


    all_aias = []
    if aia_issuers:
        for loc in aia_issuers:
            aia_uri = x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,x509.UniformResourceIdentifier(loc))
            all_aias.append(aia_uri)

    if ocsp_responders:
        for resp in ocsp_responders:
            aia_uri = x509.AccessDescription(AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier(resp))
            all_aias.append(aia_uri)

    if all_aias:
        alist = x509.AuthorityInformationAccess(all_aias)
        builder = builder.add_extension(alist,critical=False)

    print("sign CSR: == extensions ==")
    for e in csr.extensions:
        if isinstance(e.value, x509.BasicConstraints):
            print("sign CSR: %s" % (e.oid,))

            if e.value.ca:
                print("           CA=TRUE requested")

                if isca and not SETTINGS["ca"]["settings"]["grant_ca"]:
                    print("           not allowed but overridden")
                elif not SETTINGS["ca"]["settings"]["grant_ca"]:
                    print("           not allowed by rule")
                    continue
                else:
                    print("           allowed by rule")

        builder = builder.add_extension(e.value, e.critical)

    certificate = builder.sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
    return certificate


def save_certificate(cert, certfile):
    try:
        with open(os.path.join(SETTINGS['path'], certfile), "wb") as f:
            f.write(cert.public_bytes(
                encoding=serialization.Encoding.PEM))

    except Exception as e:
        print("save_certificate: exception caught: " + str(e))

def load_certificate(fnm):
    with open(fnm,'r',encoding='utf-8') as f:
        ff = f.read()
        return x509.load_pem_x509_certificate(ff.encode('ascii'), backend=default_backend())

