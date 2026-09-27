#!/usr/bin/env python3

import argparse
import atexit
import binascii
import datetime
import difflib
import fileinput
import hashlib
import importlib.util
import json
import os
import re
import shlex
import socket
import struct
import sys
import tempfile
import threading
import time
from select import select


class Features:
    have_scapy = False
    have_paramiko = False
    have_colorama = False
    have_ssl = False
    have_tls13 = False
    have_requests = False
    have_socks = False
    have_crypto = False
    have_sctp = False
    host_platform = None

    verbose = False
    debuk = False

    option_dump_received_correct = False
    option_dump_received_different = True
    option_auto_send = 5
    option_socks = None
    option_interactive = False

    fuzz_prng = None
    fuzz_level = 230

    scatter_prng = None


pplay_version = "2.0.11"

# EMBEDDED DATA BEGIN
# EMBEDDED DATA END

title = 'pplay - application payload player - %s' % (pplay_version,)
pplay_copyright = "written by Ales Stibal <astib@mag0.net>"

g_script_module = None
g_delete_files = []

g_hostname = socket.gethostname()

try:
    from scapy.all import rdpcap
    from scapy.all import IP
    from scapy.all import IPv6
    from scapy.all import TCP
    from scapy.all import UDP
    from scapy.all import SCTP
    from scapy.all import Padding

    Features.have_scapy = True
except ImportError as e:
    print('== No scapy, pcap files not supported.', file=sys.stderr)

# try to import colorama, indicate with have_ variable
try:
    import colorama
    from colorama import Fore, Back, Style

    Features.have_colorama = True
except ImportError as e:
    print('== No colorama library, enjoy.', file=sys.stderr)

# try to import ssl, indicate with have_ variable
try:
    import ssl

    Features.have_ssl = True
except ImportError as e:
    print('== No SSL python support!', file=sys.stderr)

# try to import paramiko, indicate with have_ variable
try:
    import paramiko

    Features.have_paramiko = True
except ImportError as e:
    print('== No paramiko library, use ssh with pipes!', file=sys.stderr)

# try to import paramiko, indicate with have_ variable
try:
    import requests

    Features.have_requests = True
except ImportError as e:
    print('== No requests library support, files on http(s) won\'t be accessible!', file=sys.stderr)

# try to import paramiko, indicate with have_ variable
try:
    import socks

    Features.have_socks = True
except ImportError as e:
    print('== No pysocks library support, can\'t use SOCKS proxy!', file=sys.stderr)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID
    from cryptography.x509.oid import NameOID

    Features.have_crypto = True
except ImportError as e:
    print('== no cryptography library support, can\'t use CA to sign dynamic certificates based on SNI!',
          file=sys.stderr)

try:
    import sctp

    Features.have_sctp = True
except ImportError as e:
    print('== no sctp support', file=sys.stderr)

try:
    import platform

    host_platform = platform.system()
except ImportError as e:
    print('== cannot detect your OS', file=sys.stderr)


def help_sctp():
    print()
    print_white_bright("To install support for SCTP in linux:")
    # pysctp3 from pip is **broken**
    # print("   apt install libsctp-dev libsctp1 lksctp-tools")
    # print("   pip3 install pysctp3")
    # print()

    print()
    print_red('    =!= pip version 0.7 is broken =!=')
    print()
    print("    git clone https://github.com/P1sec/pysctp/")
    print("    cd pysctp/")
    print("    python setup.py install")


def str_time():
    t = None
    failed = False
    try:
        t = datetime.now()
    except AttributeError:
        failed = True

    if not t and failed:
        try:
            t = datetime.datetime.now()
        except AttributeError:
            t = "<?>"

    return socket.gethostname() + "@" + str(t)


def print_green_bright(what):
    if Features.have_colorama:
        print(Fore.GREEN + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_green(what):
    if Features.have_colorama:
        print(Fore.GREEN + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_yellow_bright(what):
    if Features.have_colorama:
        print(Fore.YELLOW + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_yellow(what):
    if Features.have_colorama:
        print(Fore.YELLOW + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_red_bright(what):
    if Features.have_colorama:
        print(Fore.RED + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_red(what):
    if Features.have_colorama:
        print(Fore.RED + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_white_bright(what):
    if Features.have_colorama:
        print(Fore.WHITE + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_white(what):
    if Features.have_colorama:
        print(Fore.WHITE + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_blue(what):
    if Features.have_colorama:
        print(Fore.BLUE + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_blue_bright(what):
    if Features.have_colorama:
        print(Fore.BLUE + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def debuk(what):
    if Features.debuk:
        print_white(what)


def verbose(what):
    if Features.verbose:
        print_white(what)


__vis_filter = b"""................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""


def hexdump(xbuf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []

    buf = bytearray(xbuf)

    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % x for x in line])
        line = line.translate(__vis_filter).decode()
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)


def colorize(s, keywords):
    t = s
    for k in keywords:
        t = re.sub(k, Fore.CYAN + Style.BRIGHT + k + Fore.RESET + Style.RESET_ALL, t)

    return t


# download file from HTTP and store it in /tmp/, add it to g_delete_files
# so they are deleted at end of the program
def http_download_temp(url):
    try:
        r = requests.get(url, stream=True, timeout=(5, 60))
        r.raise_for_status()
    except requests.RequestException as e:
        print_red_bright("cannot download %s: %s" % (url, e))
        sys.exit(1)

    local_filename = tempfile.mkstemp(prefix="pplay_dwn_")[1]
    g_delete_files.append(local_filename)

    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)

        r.close()
        print_green("downloaded file into " + local_filename)

    return local_filename


class SxyCA:
    SETTINGS = {
        "ca": {},
        "srv": {},
        "clt": {},
        "prt": {},
        "path": "/tmp/",
        "ttl": 60
    }

    class Options:
        indent = 0
        debug = False

    @staticmethod
    def pref_choice(*args):
        for a in args:
            if a:
                return a
        return None

    @staticmethod
    def init_directories(etc_dir):

        SxyCA.SETTINGS["path"] = etc_dir

        for X in [
            SxyCA.SETTINGS["path"],
            os.path.join(SxyCA.SETTINGS["path"], "certs/"),
            os.path.join(SxyCA.SETTINGS["path"], "certs/", "default/")]:

            if not os.path.isdir(X):
                try:
                    os.mkdir(X)
                except FileNotFoundError:
                    print(SxyCA.Options.indent * " " + "fatal: path {} doesn't exit".format(X))
                    return

                except PermissionError:
                    print(SxyCA.Options.indent * " " + "fatal: Permission denied: {}".format(X))
                    return

        SxyCA.SETTINGS["path"] = os.path.join(SxyCA.SETTINGS["path"], "certs/", "default/")

    @staticmethod
    def init_settings(cn, c, ou=None, o=None, l=None, s=None, def_subj_ca=None, def_subj_srv=None, def_subj_clt=None):

        SxyCA.NameOIDMap = {
            "cn": NameOID.COMMON_NAME,
            "ou": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "o": NameOID.ORGANIZATION_NAME,
            "l": NameOID.LOCALITY_NAME,
            "s": NameOID.STATE_OR_PROVINCE_NAME,
            "c": NameOID.COUNTRY_NAME
        }

        # we want to extend, but not overwrite already existing settings
        SxyCA.load_settings()

        r = SxyCA.SETTINGS

        for k in ["ca", "srv", "clt", "prt"]:
            if k not in r:
                r[k] = {}

        for k in ["ca", "srv", "clt", "prt"]:
            if "ou" not in r[k]:
                r[k]["ou"] = SxyCA.pref_choice(ou)
            if "o" not in r[k]:
                r[k]["o"] = SxyCA.pref_choice("Smithproxy Software")
            if "s" not in r[k]:
                r[k]["s"] = SxyCA.pref_choice(s)
            if "l" not in r[k]:
                r[k]["l"] = SxyCA.pref_choice(l)
            if "c" not in r[k]:
                r[k]["c"] = SxyCA.pref_choice("CZ", c)

        if "cn" not in r["ca"]:
            r["ca"]["cn"] = SxyCA.pref_choice(def_subj_ca, "Smithproxy Root CA")
        if "cn" not in r["srv"]:
            r["srv"]["cn"] = SxyCA.pref_choice(def_subj_srv, "Smithproxy Server Certificate")
        if "cn" not in r["clt"]:
            r["clt"]["cn"] = SxyCA.pref_choice(def_subj_clt, "Smithproxy Client Certificate")
        if "cn" not in r["prt"]:
            r["prt"]["cn"] = "Smithproxy Portal Certificate"

        if "settings" not in r["ca"]:
            r["ca"]["settings"] = {
                "grant_ca": False
            }

        debuk("config to be written: %s" % (r,))

        try:
            with open(os.path.join(SxyCA.SETTINGS["path"], "sslca.json"), "w") as f:
                json.dump(r, f, indent=4)

        except Exception as e:
            print(SxyCA.Options.indent * " " + "write_default_settings: exception caught: " + str(e))

    @staticmethod
    def load_settings():

        try:
            with open(os.path.join(SxyCA.SETTINGS["path"], "sslca.json"), "r") as f:
                r = json.load(f)
                if SxyCA.Options.debug: print(SxyCA.Options.indent * " " + "load_settings: loaded settings: {}",
                                              str(r))

                SxyCA.SETTINGS = r

        except Exception as e:
            print(SxyCA.Options.indent * " " + "load_default_settings: exception caught: " + str(e))

    @staticmethod

    def generate_rsa_key(size):
        return rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())

    @staticmethod
    def load_key(fnm, pwd=None):
        with open(fnm, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=pwd, backend=default_backend())

    @staticmethod
    def generate_ec_key(curve):
        return ec.generate_private_key(curve=curve, backend=default_backend())

    @staticmethod
    def save_key(key, keyfile, passphrase=None):
        # inner function
        def choose_enc(pwd):
            if not pwd:
                return serialization.NoEncryption()
            return serialization.BestAvailableEncryption(pwd)

        try:
            with open(os.path.join(SxyCA.SETTINGS['path'], keyfile), "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=choose_enc(passphrase),
                ))

        except Exception as e:
            print(SxyCA.Options.indent * " " + "save_key: exception caught: " + str(e))

    @staticmethod
    def construct_sn(profile, sn_override=None):
        snlist = []

        override = sn_override
        if not sn_override:
            override = {}

        for subj_entry in ["cn", "ou", "o", "l", "s", "c"]:
            if subj_entry in override and subj_entry in SxyCA.NameOIDMap:
                snlist.append(x509.NameAttribute(SxyCA.NameOIDMap[subj_entry], override[subj_entry]))

            elif subj_entry in SxyCA.SETTINGS[profile] \
                    and SxyCA.SETTINGS[profile][subj_entry] \
                    and subj_entry in SxyCA.NameOIDMap:
                snlist.append(x509.NameAttribute(SxyCA.NameOIDMap[subj_entry], SxyCA.SETTINGS[profile][subj_entry]))

        return snlist

    @staticmethod
    def generate_csr(key, profile, sans_dns=None, sans_ip=None, isca=False, custom_subj=None):

        cn = SxyCA.SETTINGS[profile]["cn"].replace(" ", "-")
        sn = x509.Name(SxyCA.construct_sn(profile, custom_subj))

        sans_list = [x509.DNSName(cn)]

        if sans_dns:
            for s in sans_dns:
                if s == cn:
                    continue
                sans_list.append(x509.DNSName(s))

        if sans_ip:
            try:
                import ipaddress
                for i in sans_ip:
                    ii = ipaddress.ip_address(i)
                    sans_list.append(x509.IPAddress(ii))
            except ImportError:
                # cannot use ipaddress module
                pass

        sans = x509.SubjectAlternativeName(sans_list)

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(sn)

        if sans:
            builder = builder.add_extension(sans, critical=False)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=isca, path_length=None), critical=True)

        if isca:
            builder = builder.add_extension(x509.KeyUsage(crl_sign=True, key_cert_sign=True,
                                                          digital_signature=False, content_commitment=False,
                                                          key_encipherment=False, data_encipherment=False,
                                                          key_agreement=False, encipher_only=False,
                                                          decipher_only=False),
                                            critical=True)

        else:
            builder = builder.add_extension(x509.KeyUsage(crl_sign=False, key_cert_sign=False,
                                                          digital_signature=True, content_commitment=False,
                                                          key_encipherment=True, data_encipherment=False,
                                                          key_agreement=False, encipher_only=False,
                                                          decipher_only=False),
                                            critical=True)

            ex = [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            builder = builder.add_extension(x509.ExtendedKeyUsage(ex), critical=False)

        csr = builder.sign(key, hashes.SHA256(), default_backend())

        return csr

    @staticmethod
    def sign_csr(key, csr, caprofile, arg_valid=0, isca=False, cacert=None, aia_issuers=None, ocsp_responders=None):

        valid = 30
        if arg_valid > 0:
            valid = arg_valid
        else:
            try:
                valid = SxyCA.SETTINGS["ttl"]
            except KeyError:
                pass

        one_day = datetime.timedelta(1, 0, 0)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)

        if not cacert:
            builder = builder.issuer_name(x509.Name(SxyCA.construct_sn(caprofile)))
        else:
            builder = builder.issuer_name(cacert.subject)

        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * valid))
        # builder = builder.serial_number(x509.random_serial_number()) # too new to some systems
        builder = builder.serial_number(int.from_bytes(os.urandom(10), byteorder="big"))
        builder = builder.public_key(csr.public_key())

        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)

        # more info about issuer

        has_ski = False
        try:
            if cacert:
                ski = cacert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value),
                    critical=False)
                has_ski = True
        except AttributeError:
            #  workaround for older versions of python cryptography, not having from_issuer_subject_key_identifier
            # -> which throws AttributeError
            has_ski = False
        except x509.extensions.ExtensionNotFound:
            has_ski = False

        if not has_ski:
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                                            critical=False)

        all_aias = []
        if aia_issuers:
            for loc in aia_issuers:
                aia_uri = x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                                 x509.UniformResourceIdentifier(loc))
                all_aias.append(aia_uri)

        if ocsp_responders:
            for resp in ocsp_responders:
                aia_uri = x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                                 x509.UniformResourceIdentifier(resp))
                all_aias.append(aia_uri)

        if all_aias:
            alist = x509.AuthorityInformationAccess(all_aias)
            builder = builder.add_extension(alist, critical=False)

        if SxyCA.Options.debug: print(SxyCA.Options.indent * " " + "sign CSR: == extensions ==")

        for e in csr.extensions:
            if isinstance(e.value, x509.BasicConstraints):
                if SxyCA.Options.debug: print(SxyCA.Options.indent * " " + "sign CSR: %s" % (e.oid,))

                if e.value.ca:
                    if SxyCA.Options.debug: print((SxyCA.Options.indent + 2) * " " + "           CA=TRUE requested")

                    grant_ca = SxyCA.SETTINGS["ca"]["settings"]["grant_ca"]
                    if isinstance(grant_ca, str):
                        grant_ca = grant_ca.lower() in ("1", "true", "yes", "on")

                    if isca and not grant_ca:
                        if SxyCA.Options.debug:
                            print((SxyCA.Options.indent + 2) * " " + "           CA not allowed but overridden")
                    elif not grant_ca:
                        if SxyCA.Options.debug:
                            print((SxyCA.Options.indent + 2) * " " + "           CA not allowed by rule")
                        continue
                    else:
                        if SxyCA.Options.debug: print(
                            (SxyCA.Options.indent + 2) * " " + "           CA allowed by rule")

            builder = builder.add_extension(e.value, e.critical)

        certificate = builder.sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
        return certificate

    @staticmethod
    def save_certificate(cert, certfile):
        try:
            with open(os.path.join(SxyCA.SETTINGS['path'], certfile), "wb") as f:
                f.write(cert.public_bytes(
                    encoding=serialization.Encoding.PEM))

        except Exception as e:
            print(SxyCA.Options.indent * " " + "save_certificate: exception caught: " + str(e))

    @staticmethod
    def load_certificate(fnm):
        with open(fnm, 'r', encoding='utf-8') as f:
            ff = f.read()
            return x509.load_pem_x509_certificate(ff.encode('ascii'), backend=default_backend())


# BytesGenerator is convenient, deterministic bytes generator, which expands data
#   based on its previous state
#   given the same @magic and same sequence of rand_* requests, it will produce always
#   the same data.
class BytesGenerator:
    def __init__(self, magic, use_hash):
        self.magic = magic
        self.hash = use_hash
        use_hash.update(self.magic.encode('ascii'))
        self.state = use_hash.digest()

        rep = 0
        for i in self.state:
            rep += int(i)

        # self._strengthen(rep)

        self.pool = b''
        # update with one bock
        self._get_bytes(1)

    def _roll(self):
        self.hash.update(self.state)
        self.state = self.hash.digest()

    def _strengthen(self, times):
        rep = 0
        while rep < times:
            rep += 1
            self._roll()

    def _get_bytes(self, min_sz):

        while len(self.pool) < min_sz:
            self._roll()
            self.pool += self.state

    def rand_bytes(self, sz):
        self._get_bytes(sz)
        ret = self.pool[0:sz]
        self.pool = self.pool[sz:]

        return ret

    def rand_int(self):
        return struct.unpack('>l', self.rand_bytes(4))[0]

    def rand_uint(self):
        return struct.unpack('>L', self.rand_bytes(4))[0]

    def rand_choice(self, lst):
        return lst[self.rand_uint() % len(lst)]

    @staticmethod
    def _fillchart(beg, end, base=None):
        x = ord(beg)
        chart = [chr(x), ]
        while x <= ord(end):
            chart.append(chr(x))
            x += 1

        if base:
            return base + chart

        return chart

    def rand_str(self, sz, low_cap=True, high_cap=True, nums=True, space=False, include_list=None, exclude_list=None):
        ch = []
        if low_cap:
            ch = BytesGenerator._fillchart('a', 'z')
        if high_cap:
            ch = BytesGenerator._fillchart('A', 'Z', ch)
        if nums:
            ch = BytesGenerator._fillchart('0', '9', ch)
        if space:
            ch.append(' ')

        if include_list:
            ch += include_list

        if exclude_list:
            for ex in exclude_list:
                try:
                    ch.remove(ex)
                except ValueError as e:
                    pass

        ret = ''
        for i in range(0, sz):
            ret += ch[self.rand_uint() % len(ch)]

        return ret

    def rand_range(self, a, b):
        r = range(a, b)
        return r[self.rand_uint() % len(r)]

    def taint_str(self, orig, ceil=127, **kwargs):
        mask = self.rand_bytes(len(orig))
        ret = ''
        for i in range(0, len(orig)):
            if mask[i] > ceil:
                ret += self.rand_str(1, **kwargs)
            else:
                ret += orig[i]

        return ret

    def taint_bytes(self, orig, ceil=127, **kwargs):
        mask = self.rand_bytes(len(orig))
        ret = bytearray()
        for i in range(0, len(orig)):
            if mask[i] > ceil:
                ret += self.rand_bytes(1)
            else:
                a = orig[i]
                ret.append(a)

        return ret


class Repeater:

    def __init__(self, fnm, server_ip, custom_sport=None):

        self.fnm = fnm

        self.select_timeout = 2

        self.packets = []
        self.origins = {}

        # write this data :)
        self.to_send = b''

        # list of indexes in packets
        self.origins['client'] = []
        self.origins['server'] = []

        self.sock = None
        self.sock_upgraded = None

        self.server_port = 0
        self.custom_ip = server_ip
        self.custom_sport = custom_sport  # custom source port (only with for client connections)

        self.whoami = ""

        # index of our origin
        self.packet_index = 0

        # index of in all packets regardless of origin
        self.total_packet_index = 0

        # packet read counter (don't use it directly - for read_packet smart reads)
        self.read_packet_counter = 0

        self.use_ssl = False
        self.sslv = 0
        self.ssl_context = None
        self.ssl_cipher = None
        self.ssl_sni = None
        self.ssl_alpn = None
        self.ssl_ecdh_curve = None
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None

        self.tstamp_last_read = 0
        self.tstamp_last_write = 0
        self._last_countdown_print = 0

        self.scripter = None
        self.scripter_args = None

        self.exitoneot = False
        self.exitondiff = False
        self.nostdin = False
        self.nohexdump = False

        self.omexit = False

        self.is_udp = False
        self.is_sctp = False

        self.fuzz = False
        self.scatter = False

        # our peer (ip,port)
        self.target = (0, 0)

        # countdown timer for sending
        self.send_countdown = 0

        # ctrl-c counter (needed to break udp loop)
        self.ctrc_count = 0

        if host_platform and host_platform.startswith("Windows"):
            self.nostdin = True

        self.die_after = 0
        self.deathhand = None

    def reset(self):
        self.to_send = b''
        self.packet_index = 0
        self.total_packet_index = 0
        self.read_packet_counter = 0

    # write @txt to temp file and return its full path
    def deploy_tmp_file(self, text):
        h, fnm = tempfile.mkstemp()
        o = os.fdopen(h, "w")
        o.write(text)
        o.close()

        g_delete_files.append(fnm)
        return fnm

    def load_scripter_defaults(self):
        global g_delete_files

        if self.scripter:

            self.server_port = self.scripter.server_port
            self.packets = self.scripter.packets
            self.origins = self.scripter.origins

            has_cert = False
            has_ca = False

            if self.scripter.ssl_cert and self.scripter.ssl_key:
                has_cert = True

            if self.scripter.ssl_ca_cert and self.scripter.ssl_ca_key:
                has_ca = True

            try:
                if has_cert:
                    if self.scripter.ssl_cert and not self.ssl_cert:
                        self.ssl_cert = self.deploy_tmp_file(self.scripter.ssl_cert)

                    if self.scripter.ssl_key and not self.ssl_key:
                        self.ssl_key = self.deploy_tmp_file(self.scripter.ssl_key)

                if has_ca:
                    if self.scripter.ssl_ca_cert and not self.ssl_ca_cert:
                        self.ssl_ca_cert = self.deploy_tmp_file(self.scripter.ssl_ca_cert)
                        print("deployed temp ca cert:" + self.ssl_ca_cert)

                    if self.scripter.ssl_ca_key and not self.ssl_ca_key:
                        self.ssl_ca_key = self.deploy_tmp_file(self.scripter.ssl_ca_key)
                        print("deployed temp ca key:" + self.ssl_ca_key)
            except IOError as e:
                print("error deploying temporary files: " + str(e))

    def list_pcap(self, verbose=False, do_print=True):

        flows = {}
        ident = {}
        frame = -1
        first_ip_flow = None

        if verbose:
            print_yellow("# >>> Flow list:")

        packets = rdpcap(self.fnm)
        for packet in packets:

            frame += 1

            if packet.haslayer(IP):
                l3_layer = IP
            elif packet.haslayer(IPv6):
                l3_layer = IPv6
            else:
                continue

            try:
                sip = packet[l3_layer].src
                dip = packet[l3_layer].dst

            except IndexError as e:
                # not even IP packet
                continue

            sport = ""
            dport = ""

            # TCP
            if packet[l3_layer].haslayer(TCP):
                sport = str(packet[l3_layer][TCP].sport)
                dport = str(packet[l3_layer][TCP].dport)
                proto = "TCP"
            elif packet[l3_layer].haslayer(UDP):
                sport = str(packet[l3_layer][UDP].sport)
                dport = str(packet[l3_layer][UDP].dport)
                proto = "UDP"
            elif packet[l3_layer].haslayer(SCTP):
                sport = str(packet[l3_layer][SCTP].sport)
                dport = str(packet[l3_layer][SCTP].dport)

                print_white_bright("----")
                packet[l3_layer][SCTP].show()

                proto = "SCTP"
            else:
                proto = "Unknown"

            # Unknown
            if proto == "Unknown":
                continue

            # set a hint of the initial connection
            if not first_ip_flow:
                first_ip_flow = sip + ":" + sport

            key = proto + " / " + sip + ":" + sport + " -> " + dip + ":" + dport
            ident1 = sip + ":" + sport
            ident2 = dip + ":" + dport

            if key not in flows:
                if verbose:
                    if do_print:
                        print_yellow("%s (starting at frame %d)" % (key, frame))

                flows[key] = (ident1, ident2)

                if ident1 not in ident.keys():
                    ident[ident1] = []
                if ident2 not in ident.keys():
                    ident[ident2] = []

                ident[ident1].append(key)
                ident[ident2].append(key)

        if do_print:
            print_yellow("\n# >>> Usable connection IDs:\n")
            if verbose:
                print_white("   Yellow - probably services")
                print_white("   Green  - clients\n")

                print_white("# More than 2 simplex flows:\n"
                            "#   * source port reuse, or it's a service")
                print_white("#   * can't be used to uniquely dissect data from file.")
                print_white("--")

        candidate = None

        for unique_ident in ident.keys():

            port = unique_ident.split(":")[-1]
            no_simplex_flows = len(ident[unique_ident])

            if no_simplex_flows == 2:
                if int(port) < 1024:
                    print_yellow("   " + unique_ident + " # %d simplex flows" % (no_simplex_flows,))
                else:
                    # IANA suggests ephemeral port range starting at 49152, but many linuxes start already with 32768
                    if unique_ident == first_ip_flow and int(port) > 32768:
                        pref = "* "
                        print_green(pref + unique_ident)
                        candidate = unique_ident
                    else:
                        print_green(unique_ident)
            else:
                if do_print and verbose:
                    suffix = " # %d simplex flows" % (len(ident[unique_ident]),)
                    if Features.have_colorama:
                        suffix = Fore.RED + suffix
                    print_green(unique_ident + suffix)

        if not candidate:
            print_red("no candidate, select yourself, please.")
        return candidate

    def append_to_packets(self, origin, data_chunk):
        if isinstance(data_chunk, Padding) or type(data_chunk) == type(Padding):
            debuk("append_to_packets: ...  padding")
            return
        if not data_chunk:
            debuk("append_to_packets: ...  empty chunk")
            return

        current_index = len(self.packets)

        if self.fuzz:
            self.packets.append(bytes(Features.fuzz_prng.taint_bytes(bytes(data_chunk), ceil=Features.fuzz_level)))
        else:
            self.packets.append(bytes(data_chunk))
        self.origins[origin].append(current_index)

    # script has its data already filled, no *cap args are present -> there is noone to tamper
    # data before sending them.
    # We need to get around this and re-add them
    def scripter_refuzz(self):
        if not self.fuzz or not Features.fuzz_prng or not self.scripter:
            debuk("not refuzzing, no prng or fuzz is not set")
            return

        new_data = []

        # we need to do refuzz in the order, otherwise we would not match fuzzing order from --pcap and co
        for i in range(0, len(self.scripter.packets)):
            try:
                new_data.append(
                    bytes(Features.fuzz_prng.taint_bytes(self.scripter.packets[i], ceil=Features.fuzz_level))
                )
            except KeyError:
                debuk("what? missing some indexes in data, very weird!")

        self.scripter.packets = new_data
        self.packets = new_data

    def list_gencap(self, to_print=True):
        gen = BytesGenerator(self.fnm, hashlib.sha256())
        no_packets = gen.rand_range(2, 25)

        desc = "Generated flow size %d: " % no_packets

        for i in range(0, no_packets):
            data = gen.rand_bytes(gen.rand_range(10, 1320))
            origin = gen.rand_choice(["client", "server"])
            self.append_to_packets(origin, data)
            desc += origin + ":" + str(len(data)) + "B "

        if to_print:
            print_green(desc)

    def read_gencap(self, im_ip, im_port):
        print_yellow("generating using magic: " + self.fnm)
        self.list_gencap(to_print=False)

    def read_pcap(self, im_ip, im_port):

        packets = rdpcap(self.fnm)

        debuk("read_pcap: Looking for client connection %s:%s" % (im_ip, im_port))

        for packet in packets:

            l3_layer = None
            if packet.haslayer(IP):
                l3_layer = IP
            elif packet.haslayer(IPv6):
                l3_layer = IPv6

            try:
                sip = packet[l3_layer].src
                dip = packet[l3_layer].dst
                sport = 0
                dport = 0

                # print_white("debug: read_pcap: ip.proto " +  str(i[IP].proto))
                if packet[l3_layer].haslayer(TCP):
                    sport = str(packet[l3_layer][TCP].sport)
                    dport = str(packet[l3_layer][TCP].dport)

                elif packet[l3_layer].haslayer(UDP):
                    sport = str(packet[l3_layer][UDP].sport)
                    dport = str(packet[l3_layer][UDP].dport)

                elif packet[l3_layer].haslayer(SCTP):
                    sport = str(packet[l3_layer][SCTP].sport)
                    dport = str(packet[l3_layer][SCTP].dport)

            except IndexError as e:
                debuk("layer not found")
                continue

            debuk(">>> %s:%s -> %s:%s" % (sip, sport, dip, dport))

            origin = None

            if sip == im_ip and sport == im_port:
                origin = "client"
                if self.server_port == 0:
                    self.server_port = dport

            elif dip == im_ip and dport == im_port:
                origin = "server"

            if origin:
                extracted_payload = []

                if packet.haslayer(TCP):
                    extracted_payload.append(packet[TCP].payload)
                elif packet.haslayer(UDP):
                    extracted_payload.append(packet[UDP].payload)
                elif packet.haslayer(SCTP):
                    sctp_packet = packet[l3_layer][SCTP]

                    # looking for layer: scapy.layers.sctp.SCTPChunkData
                    counter = 0
                    while True:
                        layer = sctp_packet.getlayer(counter)
                        if layer is None:
                            break
                        else:
                            if layer.name == "SCTPChunkData":
                                extracted_payload.append(layer.data)
                        counter += 1

                else:
                    print_red("read_cap: cannot find any supported payload type in the packet")
                    continue

                if len(extracted_payload) == 0:
                    debuk("read_pcal: no payload")
                    continue

                for current_dato in extracted_payload:
                    self.append_to_packets(origin, current_dato)

    def read_smcap(self, im_ip, im_port):
        file_packets = []

        self.packets = []
        self.origins["client"] = []
        self.origins["server"] = []

        this_packet_origin = None
        this_packet_index = 0
        this_packet_bytes = []

        have_connection = False

        fin = fileinput.input(files=[self.fnm, ])
        for line in fin:
            # too heavy debug
            # debuk("Processing: " + line.strip())

            re_packet_start = re.compile(r'^\+\d+: +([^:]+):([^:]+)-([^:]+):([^:(]+)')
            re_packet_content_client = re.compile(r'^>\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')
            re_packet_content_server = re.compile(r'^ +<\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')

            sip = None
            dip = None
            sport = None
            dport = None

            if not have_connection:
                m = re_packet_start.search(line)
                if m:
                    # print_yellow_bright("Packet start: " + line.strip())
                    sip = m.group(1)
                    dip = m.group(3)
                    sport = m.group(2)
                    dport = m.group(4)
                    # print_yellow_bright("%s:%s -> %s:%s" % (sip,sport,dip,dport))
                    have_connection = True

                    self.server_port = dport

                    if sip.startswith("udp_"):
                        self.is_udp = True

            matched = False
            m = None

            if not matched:
                m = re_packet_content_client.search(line)
                if m:
                    # print_green_bright(line.strip())
                    # print_green(m.group(2))
                    this_packet_bytes.append(m.group(2))
                    this_packet_origin = 'client'
                    matched = True

            if not matched:
                m = re_packet_content_server.search(line)
                if m:
                    # print_red(m.group(2))
                    this_packet_bytes.append(m.group(2))
                    this_packet_origin = 'server'
                    matched = True

            if not matched:
                if this_packet_bytes:
                    # finalize packet

                    data = self.smcap_convert_lines_to_bytes(this_packet_bytes)

                    self.append_to_packets(this_packet_origin, data)

                    this_packet_bytes = []
                    this_packet_origin = None
                    this_packet_index += 1

        # SMCAP files do not have to end with a blank/separator line.
        if this_packet_bytes:
            data = self.smcap_convert_lines_to_bytes(this_packet_bytes)
            self.append_to_packets(this_packet_origin, data)

    @staticmethod
    def smcap_convert_lines_to_bytes(list_of_ords):
        bytes = b''

        for l in list_of_ords:
            for oord in l.split(" "):
                if oord:
                    bytes += binascii.unhexlify(oord)

        return bytes

    def list_smcap(self, args=None):

        fin = fileinput.input(files=[self.fnm, ])
        for line in fin:
            re_packet_start = re.compile(
                r'^\+\d+: [a-z+]+_([^ ^(]+)(?=:[0-9]+):([0-9]+)-[a-z+]+_([^ ^(]+)(?=:[0-9]+):([0-9]+)\([a-z+]+_([^ ^(]+)(?=:[0-9]+):([0-9]+)-[a-z+]+_([^ ^(]+)(?=:[0-9]+):([0-9]+)\)')

            sip = None
            dip = None
            sport = None
            dport = None
            have_connection = False

            if not have_connection:
                m = re_packet_start.search(line)
                if m:
                    # print_yellow_bright("Packet start: " + line.strip())
                    sip = m.group(1)
                    dip = m.group(3)
                    sport = m.group(2)
                    dport = m.group(4)

                    if sip.startswith("udp_"):
                        self.is_udp = True

                    fin.close()

                    n = sip.find("_")
                    if 0 <= n < len(sip) - 1:
                        sip = sip[n + 1:]

                    n = dip.find("_")
                    if 0 <= n < len(dip) - 1:
                        dip = dip[n + 1:]

                    if args:
                        if args == "sip":
                            print("%s" % (sip,), file=sys.stderr)
                            return sip
                        elif args == "dip":
                            print("%s" % (dip,), file=sys.stderr)
                            return dip
                        elif args == "sport":
                            print("%s" % (sport,), file=sys.stderr)
                            return sport
                        elif args == "dport":
                            print("%s" % (dport,), file=sys.stderr)
                            return dport
                        elif args == "proto":
                            if self.is_udp:
                                print("udp", file=sys.stderr)
                                return "udp"
                            else:
                                print("tcp", file=sys.stderr)
                                return "tcp"

                    else:
                        print_yellow(
                            "%s:%s -> %s:%s  (single connection per file in smcap files)" % (sip, sport, dip, dport))
                        return "%s:%s" % (sip, sport)

    def export_self(self, efile):

        ssource = self.export_script(None)
        out = ''

        with open(__file__) as f:
            lines = f.read().split('\n')

            for single_line in lines:
                out += single_line
                out += "\n"

                # print("export line: %s" % (single_line))
                if single_line == "# EMBEDDED DATA BEGIN":
                    out += "\n"
                    out += ssource
                    out += "\n"

                    out += "pplay_version = \"" + str(pplay_version) + "-" + hashlib.sha1(
                        ssource.encode('utf-8')).hexdigest() + "\"\n"

        with open(efile, "w") as o:
            o.write(out)
            os.chmod(efile, 0o755)
            debuk("pack: using " + efile)

    def export_script(self, efile):

        if efile and os.path.isfile(efile):
            print_red_bright("refusing to overwrite already existing file!")
            return None

        c = "__pplay_packed_source__ = True\n\n\n\n"
        c += "class PPlayScript:\n\n"
        c += "    def __init__(self, pplay=None, args=None):\n"
        c += "        # access to pplay engine\n"
        c += "        self.pplay = pplay\n\n"
        c += "        self.packets = []\n"
        c += "        self.args = args\n"

        for p in self.packets:
            c += "        self.packets.append(%s)\n\n" % (repr(p),)

        c += "        self.origins = {}\n\n"
        c += "        self.server_port = %s\n" % (self.server_port,)
        c += "        self.custom_sport = %s\n" % (self.custom_sport,)

        for k in self.origins.keys():
            c += "        self.origins['%s']=%s\n" % (k, self.origins[k])

        c += "\n\n"

        if self.ssl_cert:
            with open(self.ssl_cert) as ca_f:
                c += "        self.ssl_cert=\"\"\"\n" + ca_f.read() + "\n\"\"\"\n"
        else:
            c += "        self.ssl_cert=None\n"

        if self.ssl_key:
            with open(self.ssl_key) as key_f:
                c += "        self.ssl_key=\"\"\"\n" + key_f.read() + "\n\"\"\"\n"
        else:
            c += "        self.ssl_key=None\n"

        c += "\n\n"
        if self.ssl_ca_cert:
            with open(self.ssl_ca_cert) as ca_f:
                c += "        self.ssl_ca_cert=\"\"\"\n" + ca_f.read() + "\n\"\"\"\n"
        else:
            c += "        self.ssl_ca_cert=None\n"

        if self.ssl_ca_key:
            with open(self.ssl_ca_key) as key_f:
                c += "        self.ssl_ca_key=\"\"\"\n" + key_f.read() + "\n\"\"\"\n"
        else:
            c += "        self.ssl_ca_key=None\n"

        c += "\n\n"
        c += """
    def before_send(self,role,index,data):
        # when None returned, no changes will be applied and packets[ origins[role][index] ] will be used
        return None

    def after_received(self,role,index,data):
        # return value is ignored: use it as data gathering for further processing
        return None
        """

        if not efile:

            return c
        else:
            with open(efile, 'w', encoding='utf-8') as f:
                f.write(c)

        return None

    # this is safety measure - kill itself ungracefully after specified time in seconds elapses
    def killer_is_me(self):
        while True:
            time.sleep(1)
            if self.die_after < 0:
                sys.stdout.flush()

                # -10 is cancel signal
                if self.die_after > -10:
                    print_red("killed by the deathhand")
                    cleanup()
                    os._exit(-15)  # don't mess with other threads and just finish it
                else:
                    return

            self.die_after -= 1

    # for spaghetti lovers
    def impersonate(self, who):

        if self.die_after > 0:
            self.deathhand = threading.Thread(target=Repeater.killer_is_me, args=(self,))
            self.deathhand.start()

        if who == "client":
            self.impersonate_client()
        elif who == "server":
            self.impersonate_server()

    def send_aligned(self):

        if self.packet_index < len(self.origins[self.whoami]):
            return self.total_packet_index >= self.origins[self.whoami][self.packet_index]
        return False

    def send_issame(self):
        if self.packet_index < len(self.origins[self.whoami]):
            return self.packets[self.origins[self.whoami][self.packet_index]] == self.to_send
        return False

    def ask_to_send(self, xdata=None):

        data = None
        if xdata is None:
            data = self.to_send
        else:
            data = xdata

        aligned = ''
        if self.send_aligned():
            aligned = '(in-sync'
        else:
            aligned = '(off-sync'

        if not self.send_issame():
            if aligned:
                aligned += ", modified"
            else:
                aligned += "(modified"

        if aligned:
            aligned += ") "

        out = "# [%d/%d]: %s" % (self.packet_index + 1, len(self.origins[self.whoami]), aligned)
        if self.send_aligned():
            print_green_bright(out)
        else:
            print_yellow(out)

        out = ''
        if self.nohexdump:
            out = "# ... offer to send %dB of data (hexdump suppressed): " % (len(data),)
        else:
            out = hexdump(data)

        if self.send_aligned():
            print_green(out)
        # 
        # dont print hexdumps of unaligned data
        # else:
        #    print_yellow(out)

        if Features.option_auto_send < 0 or Features.option_auto_send >= 5:

            out = ''
            out += "#<--\n"
            out += "#--> SEND IT TO SOCKET? [ y=yes (default) | s=skip | c=CR | l=LF | x=CRLF ]\n"
            out += "#    For more commands or help please enter 'h'.\n"

            if self.send_aligned():
                print_green_bright(out)
            else:
                print_yellow(out)

    def ask_to_send_more(self):

        if not self.nostdin:
            print_yellow_bright("#--> SEND MORE INTO SOCKET? [ c=CR | l=LF | x=CRLF | N=new data]")

    def starttls(self):
        if Features.have_ssl:
            self.use_ssl = True
            self.sock = self.prepare_socket(self.sock, self.whoami == 'server')
            self.sock_upgraded = self.sock

            return True
        else:
            return False

    def prepare_ssl_socket(self, s, server_side, on_sni=False):

        if self.sslv == 3:
            print_red("SSLv3")
            # ssl3
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            self.ssl_context.options &= ~ssl.OP_NO_SSLv3
            self.ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                                         | ssl.OP_NO_TLSv1_3)

        elif self.sslv == 4:
            print_red("requiring TLSv1")
            # tls1
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1
            self.ssl_context.options |= (ssl.OP_NO_SSLv2 & ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                                         | ssl.OP_NO_TLSv1_3)

        elif self.sslv == 5:
            print_red("requiring TLSv1.1")
            # tls1.1
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1_1
            self.ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2
                                         | ssl.OP_NO_TLSv1_3)
            self.ssl_context.set_ciphers("ALL:!LOW")

        elif self.sslv == 6:
            print_red("requiring TLSv1.2")
            # tls1.2
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                                         | ssl.OP_NO_TLSv1_3)
            self.ssl_context.set_ciphers("ALL:!LOW")

        elif self.sslv > 6:
            print_red("requiring TLSv1.3 or better")
            # tls1.3

            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self.ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                                         | ssl.OP_NO_TLSv1_2)

        else:
            print_red("TLS version will be negotiated")
            if server_side:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            else:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        try:
            self.ssl_context.keylog_file = "/tmp/sslkeys"
        except AttributeError as e:
            print_red("no sslkeylogfile support")

        if self.ssl_cipher:
            self.ssl_context.set_ciphers(self.ssl_cipher)

        if self.ssl_ecdh_curve:
            self.ssl_context.set_ecdh_curve(self.ssl_ecdh_curve)

        if not server_side:

            if self.ssl_alpn:
                self.ssl_context.set_alpn_protocols(self.ssl_alpn)

            return self.ssl_context.wrap_socket(s, server_hostname=self.ssl_sni, suppress_ragged_eofs=True)
        else:
            if self.ssl_cert and self.ssl_key:
                self.ssl_context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
            elif self.ssl_ca_cert and self.ssl_ca_key:
                # make TLS1.3 and load some keys
                self.ssl_context.load_cert_chain(certfile=self.ssl_ca_cert, keyfile=self.ssl_ca_key)

            if not on_sni:
                try:
                    self.ssl_context.sni_callback = self.imp_server_ssl_callback
                except AttributeError:
                    # older python3 versions
                    self.ssl_context.set_servername_callback(self.imp_server_ssl_callback)

                return self.ssl_context.wrap_socket(s, server_side=True)
            else:
                s.context = self.ssl_context
                return s

    def prepare_socket(self, s, server_side=False):
        if Features.have_ssl and self.use_ssl:
            return self.prepare_ssl_socket(s, server_side)
        else:
            return s

    def create_socket(self, is_client, proto_ver=4):
        global g_script_module

        if self.is_udp:
            if proto_ver == 6:
                if self.is_sctp and Features.have_sctp:
                    new_socket = sctp.sctpsocket_udp(socket.AF_INET6)
                else:
                    new_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                if self.is_sctp and Features.have_sctp:
                    new_socket = sctp.sctpsocket_udp(socket.AF_INET)
                else:
                    new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            if is_client and Features.option_socks:
                debuk("SOCKS socket init")

                new_socket = socks.socksocket()
                if len(Features.option_socks) > 1:
                    new_socket.set_proxy(socks.SOCKS5, Features.option_socks[0], int(Features.option_socks[1]))
                else:
                    new_socket.set_proxy(socks.SOCKS5, Features.option_socks[0], int(1080))
            else:
                if proto_ver == 6:
                    if self.is_sctp and Features.have_sctp:
                        new_socket = sctp.sctpsocket_tcp(socket.AF_INET6)
                    else:
                        new_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    if self.is_sctp and Features.have_sctp:
                        new_socket = sctp.sctpsocket_tcp(socket.AF_INET)
                    else:
                        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                if not self.is_sctp:
                    new_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if not is_client and not self.is_udp:
            new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        return new_socket

    def impersonate_client(self):
        global g_script_module

        if g_script_module and not self.scripter:
            self.scripter = g_script_module.PPlayScript(self, self.scripter_args)
            self.load_scripter_defaults()

        try:
            self.whoami = "client"

            ip = self.custom_ip
            port = int(self.server_port)

            t = ip.split(":")
            if len(t) > 1:
                ip, port, im_ver = address_pair(ip)
                port = int(port)
            else:
                im_ver = 4
                try:
                    port = int(ip)
                    ip = "localhost"
                except ValueError:
                    print_red("using original destination port from sample data")

            if port == 0:
                port = int(self.server_port)

            self.target = (ip, port)

            print_ip = ip
            if im_ver == 6:
                print_ip = "[" + print_ip + "]"
            print_white_bright("IMPERSONATING CLIENT, connecting to %s:%s" % (print_ip, port,))

            new_socket = None

            self.sock = self.create_socket(True, im_ver)

            try:
                if self.custom_sport:
                    self.sock.bind(('', int(self.custom_sport)))

                self.sock.connect((ip, int(port)))
            except socket.error as e:
                print_white_bright(" === ")
                print_white_bright("   Connecting to %s:%s failed: %s" % (ip, port, e))
                print_white_bright(" === ")
                return

            try:
                self.sock = self.prepare_socket(self.sock, False)
                self.packet_loop()

            except socket.error as e:
                print_white_bright(" === ")
                print_white_bright("   Connection to %s:%s failed: %s" % (ip, port, e))
                print_white_bright(" === ")
                return

        except KeyboardInterrupt as e:
            print_white_bright("\nCtrl-C: bailing it out.")
            self.die_after = -10
            return

    def imp_server_ssl_callback(self, sock, sni, ctx):
        print_white("requested SNI: %s" % (sni,))
        if not sni:
            if self.ssl_sni:
                print_yellow("using default explicit SNI: " + self.ssl_sni)
                sni = self.ssl_sni
            else:
                sni = "server.pplay.cloud"
                print_yellow("using fallback SNI: " + sni)

        if not Features.have_crypto:
            # no cryptography ... ok - either we have server cert provided, or we are doomed.

            if not self.ssl_cert or not self.ssl_key:
                print_red_bright("neither having cryptography (no CA signing), nor certificate pair")
                print_red_bright("this won't end up well.")
            return

        try:
            sslca_root = "/tmp/pplay-ca"
            SxyCA.init_directories(sslca_root)
            SxyCA.init_settings(cn=None, c=None)
            SxyCA.load_settings()

            if self.ssl_ca_cert and self.ssl_ca_key:
                ca_key = SxyCA.load_key(self.ssl_ca_key)
                ca_cert = SxyCA.load_certificate(self.ssl_ca_cert)

                prt_key = SxyCA.generate_rsa_key(2048)
                prt_csr = SxyCA.generate_csr(prt_key, "srv", sans_dns=[sni, ], sans_ip=None,
                                             custom_subj={"cn": sni})
                prt_cert = SxyCA.sign_csr(ca_key, prt_csr, "srv", cacert=ca_cert)

                tmp_key_file = \
                    tempfile.mkstemp(dir=os.path.join(sslca_root, "certs/", "default/"), prefix="sni-key-")[1]
                g_delete_files.append(tmp_key_file)

                tmp_cert_file = \
                    tempfile.mkstemp(dir=os.path.join(sslca_root, "certs/", "default/"), prefix="sni-cert-")[1]
                g_delete_files.append(tmp_cert_file)

                SxyCA.save_key(prt_key, os.path.basename(tmp_key_file))
                SxyCA.save_certificate(prt_cert, os.path.basename(tmp_cert_file))

                self.ssl_key = tmp_key_file
                self.ssl_cert = tmp_cert_file

                self.prepare_ssl_socket(sock, server_side=True, on_sni=True)

                print_green("spoofing cert for sni:%s finished" % (sni,))
            else:
                print_red("CA key or CA cert not specified, fallback to pre-set certificate")

        except Exception as e:
            print_red("error in SNI handler: " + str(e))
            print_red("fallback to pre-set certificate")
            raise e

    def accept(self, s):
        conn, client_address = None, ["", ""]

        if not self.is_udp:
            while True:
                readable, writable, errored = select([s, ], [], [], self.select_timeout)
                if s in readable:
                    break
                else:
                    # timeout
                    if self.detect_parent_death():
                        self.on_parent_death()

            conn, client_address = s.accept()
            self.target = client_address
            print_white_bright("accepted client from %s:%s" % (client_address[0], client_address[1]))
        else:
            conn = s
            client_address = ["", ""]

        return conn, client_address

    def impersonate_server(self):
        global g_script_module

        orig_use_ssl = self.use_ssl

        try:
            ip = "::"
            port = int(self.server_port)
            im_ver = 6

            if self.custom_ip:

                t = self.custom_ip.split(":")
                if len(t) > 1:
                    ip, port, im_ver = address_pair(self.custom_ip)
                    port = int(port)

                elif len(t) == 1:
                    # assume it's port
                    port = int(t[0])

                # if specified port is 0, use original port in the capture
                if port == 0:
                    port = int(self.server_port)

                debuk("custom IP:PORT %s:%d" % (ip, port))

            self.whoami = "server"

            print_ip = ip
            if im_ver == 6:
                print_ip = "[" + print_ip + "]"
            print_white_bright("IMPERSONATING SERVER, listening on %s:%s" % (print_ip, port,))

            server_address = (ip, int(port))

            s = self.create_socket(False, im_ver)

            s.bind(server_address)

            if not self.is_udp:
                s.listen(1)

            self.ctrc_count = 0
            while True:
                self.reset()
                print_white("waiting for new connection...")

                conn, client_address = self.accept(s)

                # flush stdin before real commands are inserted
                sys.stdin.flush()

                # use_ssl might get changed, ie with some STARTTLS operation
                self.use_ssl = orig_use_ssl
                conn = self.prepare_socket(conn, True)
                self.sock = conn

                try:
                    if g_script_module:
                        self.scripter = g_script_module.PPlayScript(self, self.scripter_args)
                        self.load_scripter_defaults()

                    self.packet_loop()
                except KeyboardInterrupt as e:
                    self.die_after = -10
                    self.ctrc_count += 1
                    if self.ctrc_count > 1:
                        sys.exit(0)

                    print_white_bright(
                        "\nCtrl-C: hit in client loop, exiting to accept loop. Hit Ctrl-C again to terminate.")

                    # we don't accept new sockets, therefore we can't close this one!
                    if not self.is_udp:
                        self.sock.close()

                except socket.error as e:
                    print_white_bright(
                        "\nConnection with %s:%s terminated: %s" % (client_address[0], client_address[1], e,))

                    if self.exitoneot:

                        # clean up death timer
                        if self.deathhand:
                            self.die_after = -10

                        sys.exit(0)

                    if self.is_udp:
                        break

        except KeyboardInterrupt as e:
            print_white_bright("\nCtrl-C: bailing it out.")
            self.die_after = -10
            return
        except socket.error as e:
            print_white_bright("Server error: %s" % (e,))
            sys.exit(16)

    def recv(self, pending):
        if self.is_sctp and not self.use_ssl:
            xp = pending
            if pending == 0:
                xp = 20 * 1024
            fromaddr, flags, msg, notif = self.sock.sctp_recv(xp)

            return msg
        else:
            return self.sock.recv(pending)

    def read(self, data_left, blocking=True):

        debuk("read(): blocking %d" % blocking)

        if Features.have_ssl and self.use_ssl:
            data = b''

            self.sock.setblocking(blocking)
            cur_data_left = data_left
            while True:
                try:
                    pen = self.sock.pending()
                    debuk("SSL: pending: %dB, expecting %dB of data (stage 1)" % (pen, cur_data_left))

                    if pen == 0:
                        pen = 10240

                    to_read = min(pen, cur_data_left)
                    debuk("SSL: reading: %dB of data (stage 1)" % (to_read,))
                    red = self.recv(to_read)

                    data += red
                    cur_data_left -= len(red)

                except ssl.SSLError as e:
                    debuk("read(): ssl error: %s" % (str(e),))
                    # Ignore the SSL equivalent of EWOULDBLOCK, but re-raise other errors

                    if e.errno != ssl.SSL_ERROR_WANT_READ:
                        raise
                    continue

                except SystemError as e:
                    debuk("read(): system error: %s" % (str(e),))

                # continue to read data until we got size of expected data
                attempts = 0
                while cur_data_left > 0:
                    attempts += 1
                    debuk("SSL: expecting/reading: %dB of data" % cur_data_left)
                    red = self.recv(cur_data_left)
                    if len(red) == 0 and attempts > 50:
                        debuk("SSL: connection data staled")
                        break

                    data += red
                    cur_data_left -= len(red)

                # if we got here, break (we have all data we wanted)
                break

            self.tstamp_last_read = time.time()
            self.sock.setblocking(True)
            return data
        else:
            debuk("expecting/reading: %dB of data" % data_left)
            self.tstamp_last_read = time.time()
            if not self.is_udp:
                self.sock.setblocking(True)
                return self.recv(data_left)
            else:
                data, client_address = self.sock.recvfrom(data_left)
                self.target = client_address
                self.sock.setblocking(True)
                return data

    def send(self, what):
        if self.is_sctp and not self.use_ssl:
            return self.sock.sctp_send(what)
        else:
            return self.sock.send(what)

    def sendto(self, what, whom):
        if self.is_sctp:
            return self.sock.sctp_send(what)
        else:
            return self.sock.sendto(what, whom)

    def write(self, data):

        if not data:
            return 0

        data_len = len(data)
        already_written = 0

        if Features.have_ssl and self.use_ssl:
            self.tstamp_last_write = time.time()
            while already_written < data_len:

                r = self.send(data[already_written:])
                if r == 0:
                    raise ConnectionError("socket connection broken during write")
                already_written += r

                # print warning
                if r != data_len:
                    print_red_bright("debug write: sent %d out of %d" % (already_written, data_len))

            return already_written

        else:
            self.tstamp_last_write = time.time()
            if not self.is_udp:
                while already_written < data_len:
                    r = self.send(data[already_written:])
                    if r == 0:
                        raise ConnectionError("socket connection broken during write")
                    already_written += r

                    if r != data_len:
                        print_red_bright("debug write: sent %d out of %d" % (already_written, data_len))

                return already_written

            else:
                return self.sendto(data, self.target)

    def load_to_send(self, role, role_index):
        who = self
        if self.scripter:
            who = self.scripter

        to_send_idx = who.origins[role][role_index]
        return who.packets[to_send_idx]

    def send_to_send(self):

        if self.to_send:
            orig_index = self.packet_index

            if self.scripter:
                try:
                    modified = self.scripter.before_send(self.whoami, orig_index, str(self.to_send))
                except AttributeError:
                    modified = None

                if modified is not None:
                    print_yellow_bright("# data modified by script!")
                    if isinstance(modified, str):
                        modified = modified.encode("utf-8")
                    self.to_send = bytes(modified)

            been_sent = self.to_send
            self.packet_index += 1
            self.total_packet_index += 1

            total_data_len = len(self.to_send)
            total_written = 0

            scattered_count = 0

            while total_written != total_data_len:

                if self.scatter and Features.scatter_prng and \
                        not len(self.to_send) < 10 and not self.is_udp and scattered_count < 3:

                    max_send = Features.scatter_prng.rand_range(5, len(self.to_send))
                    cnt = self.write(self.to_send[0:max_send])
                    scattered_count += 1
                    time.sleep(0.01 * Features.scatter_prng.rand_range(1, 20))
                else:
                    cnt = self.write(self.to_send)

                # not really clean debug, lots of data will be duplicated
                # if cnt > 200: cnt = 200

                data_len = len(self.to_send)

                if cnt == data_len:
                    print_green_bright("# ... %s [%d/%d]: has been sent (%d bytes)" % (
                        str_time(), self.packet_index, len(self.origins[self.whoami]), cnt))
                else:
                    print_green_bright("# ... %s [%d/%d]: has been sent (ONLY %d/%d bytes)" % (
                        str_time(), self.packet_index, len(self.origins[self.whoami]), cnt, data_len))
                    self.to_send = self.to_send[cnt:]

                total_written += cnt

            self.to_send = None

            if self.scripter:
                try:
                    self.scripter.after_send(self.whoami, orig_index, str(been_sent))
                except AttributeError:
                    pass

    def detect_parent_death(self):
        # mypid = os.getpid()
        # parpid = os.getppid()

        # debuk("mypid %s, parent pid %s" % (str(mypid), str(parpid),))

        return os.getppid() == 1

    def on_parent_death(self):
        sys.exit(-2)

    def select_wrapper(self, no_writes):
        global host_platform

        inputs = [self.sock, sys.stdin]
        if self.nostdin:
            # debuk("STDIN will not be used")
            inputs = [self.sock, ]

        outputs = [self.sock]
        if no_writes:
            outputs.remove(self.sock)

        if Features.have_ssl and self.use_ssl:
            r = []
            w = []
            e = []

            if self.sock.pending():
                r.append(self.sock)  # if there are bytes,

            if not no_writes:
                w.append(self.sock)  # FIXME: we assume we can always write without select

            rr, ww, ee = select(inputs, outputs, [], self.select_timeout)
            if self.sock in rr:
                r.append(self.sock)
            if sys.stdin in rr:
                r.append(sys.stdin)

            if self.detect_parent_death():
                self.on_parent_death()

            return r, w, e

        else:

            r, w, e = select(inputs, outputs, [], self.select_timeout)
            if self.detect_parent_death():
                self.on_parent_death()

            return r, w, e

    def is_eot(self):
        return self.total_packet_index >= len(self.packets)

    def get_expected_data_len(self):
        try:
            return len(self.packets[self.total_packet_index])
        except IndexError:
            # let's expect whatever we can receive
            return 0

    def packet_read(self):
        debuk("packet_read: reading socket")

        d = self.read(self.get_expected_data_len())
        current_len = len(d)

        debuk("packet_read: read returned %d" % len(d))
        if not len(d):
            return len(d)

        expected_data = self.packets[self.total_packet_index]

        # wait for some time
        loopcount = 0
        len_expected_data = len(expected_data)
        len_d = len(d)
        t_start = time.time()

        while len_d < len_expected_data:

            if current_len != 0:
                print_red("# ... %s: received partial %dB/%dB " % (str_time(), len(d), len_expected_data))
            # verbose("incomplete data: %d/%d" % (len_d,len_expected_data))
            loopcount += 1

            delta = time.time() - t_start
            if delta > 1:
                if Features.verbose:
                    print_yellow("data receiving delay...")
                time.sleep(0.05)

            if delta > 10:
                print_red_bright("receiving timed out!")
                break

            data = self.read(self.get_expected_data_len() - len(d))
            current_len = len(data)
            d += data
            len_d = len(d)

            if len_d < len_expected_data:
                verbose("expecting: %dB more" % (len_expected_data - len_d,))
        else:
            verbose("finished data: %d/%d" % (len_d, len_expected_data))

        # there are still some data to send/receive
        if self.total_packet_index < len(self.packets):
            # test if data are as we should expect
            aligned = False

            # if auto is enabled, we will not wait for user input when we received already some packet
            # user had to start pplay on the other side
            if Features.option_auto_send:
                self.auto_send_now = time.time()

            # to print what we got and what we expect
            # print_white_bright(hexdump(d))
            # print_white_bright(hexdump(self.packets[self.total_packet_index]))

            scripter_flag = ""
            if self.scripter:
                scripter_flag = " (sending to script)"

            different = False
            if d == self.packets[self.total_packet_index]:
                aligned = True
                self.total_packet_index += 1
                print_red_bright("# ... %s: received %dB OK%s" % (str_time(), len(d), scripter_flag))

            else:
                self.total_packet_index += 1
                print_red_bright(r"# !!! /!\ DIFFERENT DATA /!\ !!!")
                different = True

                if not host_platform or not host_platform.startswith("Windows"):
                    smatch = difflib.SequenceMatcher(None, bytes(d).decode("ascii", errors='ignore'),
                                                     bytes(self.packets[self.total_packet_index - 1]).decode("ascii",
                                                                                                             errors='ignore'),
                                                     autojunk=False)
                    qr = smatch.ratio()
                    if qr > 0.05:
                        print_red_bright(
                            "# !!! %s received %sB modified (%.1f%%)%s" % (str_time(), len(d), qr * 100, scripter_flag))
                    else:
                        print_red_bright(
                            "# !!! %s received %sB of different data%s" % (str_time(), len(d), scripter_flag))
                else:
                    print_red_bright("# !!! %s received %sB of different data%s" % (str_time(), len(d), scripter_flag))

            if self.scripter:
                try:
                    self.scripter.after_received(self.whoami, self.packet_index, str(d))
                except AttributeError:
                    pass
                # print_red_bright("# received data processed")

            # this block is printed while in the normal packet loop (there are packets still to receive or send
            if aligned:
                if Features.option_dump_received_correct:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")
            else:
                if Features.option_dump_received_different:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")

            if different:

                if Features.verbose:
                    print_yellow_bright("# !!! Expected data:")
                    # index-1, because we incremented it already
                    print_yellow(hexdump(self.packets[self.total_packet_index - 1]))

                if self.exitondiff:
                    print_red_bright("\n>>> Different data received, exiting.\n")
                    sys.exit(2)

        # this block means there is nothing to send/receive
        else:
            if Features.option_dump_received_different:
                print_red_bright("#-->")
                print_red(hexdump(d))
                print_red_bright("#<--")

        # we have already data to send prepared!
        if self.to_send:
            #  print, but not block
            self.ask_to_send(self.to_send)
        else:
            self.ask_to_send_more()

        return len(d)

    def packet_write(self, cmd_hook=False):

        if self.packet_index >= len(self.origins[self.whoami]):
            print_yellow_bright("# [EOT]")
            self.ask_to_send_more()
            # if we have nothing to send, remove conn from write set
            self.to_send = None
            self.write_end = True
            return
        else:

            if not self.to_send:
                self.to_send = self.load_to_send(self.whoami, self.packet_index)

                # to_send_2 = None
                # if self.scripter:
                # try:
                # to_send_2 = self.scripter.before_send(self.whoami,self.packet_index,str(self.to_send))

                # except AttributeError:
                ## scripter doesn't have before_send implemented
                # pass

                # if to_send_2 != None:
                # print_yellow_bright("# data modified by script!")
                # self.to_send = to_send_2

                self.ask_to_send(self.to_send)

            else:

                if cmd_hook:
                    l = sys.stdin.readline()

                    # readline can return empty string
                    if len(l) > 0:
                        # print_white("# --> entered: '" + l + "'")
                        self.process_command(l.strip(), 'ysclxrihN')

                        # in auto mode, reset current state, since we wrote into the socket
                        if Features.option_auto_send:
                            self.auto_send_now = time.time()
                            return

                # debuk("debug: autosend = " + str(Features.option_auto_send))

                # auto_send feature
                if Features.option_auto_send > 0 and self.send_aligned():

                    now = time.time()
                    if self._last_countdown_print == 0:
                        self._last_countdown_print = now

                    delta = now - self._last_countdown_print
                    # print out the dot
                    if delta >= 1:

                        self.send_countdown = round(self.auto_send_now + Features.option_auto_send - now)

                        # print dot only if there some few seconds to indicate
                        if Features.option_auto_send >= 2:
                            # print(".",end='',file=sys.stderr)
                            # print(".",end='',file=sys.stdout)
                            if self.send_countdown > 0:
                                print("..%d" % (self.send_countdown,), end='\n', file=sys.stdout)
                                sys.stdout.flush()

                        self._last_countdown_print = now

                    if now - self.auto_send_now >= Features.option_auto_send:

                        # indicate sending only when there are few seconds to indicate
                        if Features.option_auto_send >= 2:
                            print_green_bright("  ... sending!")

                        self.send_to_send()
                        self.auto_send_now = now

    def packet_loop(self):

        running = 1
        self.write_end = False
        self.auto_send_now = time.time()
        eof_notified = False

        while running:
            # time.sleep(0.2)
            # print_red(".")

            if self.is_eot():

                debuk("is_eot is true")

                if not eof_notified:
                    print_red_bright("### END OF TRANSMISSION ###")
                    eof_notified = True

                if self.exitoneot:
                    debuk("exitoneot true")

                    if self.whoami == "server":
                        if Features.option_auto_send >= 0:
                            time.sleep(Features.option_auto_send)
                        else:
                            time.sleep(0.5)

                    print_red("Exiting on EOT")

                    # clean up death timer
                    if self.deathhand:
                        self.die_after = -10

                    if not self.is_udp:
                        self.sock.shutdown(socket.SHUT_WR)

                    if self.whoami == 'client':
                        # sleep a while on client
                        time.sleep(2)

                    self.sock.close()
                    sys.exit(0)

                # we won't be notified on socket close in case of UDP and next dgram would be understood as belonging
                # to this connection - that is typically not the case - next packet is usually new connection attempt.
                # we have to return now to re-init the loop and not doing select
                #
                # in case of TCP (or other streams), we would terminate connection even if --exitoneot is not set
                # end even we want to keep the session up
                if self.is_udp:
                    break

            r, w, e = self.select_wrapper(self.write_end)

            if r or e or not w:
                debuk("DEBUG: sockets: r %s, w %s, e %s" % (str(r), str(w), str(e)))

            if self.sock in r and not self.send_aligned():

                l = self.packet_read()

                if l == 0:
                    print_red_bright("#--> connection closed by peer")
                    if self.exitoneot:
                        print_red("Exiting on EOT")

                        # clean up death timer
                        if self.deathhand:
                            self.die_after = -10

                        if not self.is_udp:
                            self.sock.shutdown(socket.SHUT_WR)
                        self.sock.close()
                        sys.exit(0)

                    break
                else:
                    # on data: reset ctrc_count for connectionless ... connections :-)
                    self.ctrc_count = 0

            if self.sock in w and not self.write_end:
                self.packet_write(cmd_hook=(sys.stdin in r))

            if self.write_end and sys.stdin in r:
                l = sys.stdin.readline()
                if len(l) > 0:
                    self.process_command(l.strip(), 'yclxN')

                if self.to_send:
                    self.ask_to_send()
                else:
                    self.ask_to_send_more()

    def cmd_replace(self, command, data):
        # something like vim's replace:  r/something/smtelse/0

        if len(command) > 1:

            parts = command.split(command[1])
            # print_yellow(str(parts))
            if len(parts) == 4:
                source = data.decode("latin-1") if isinstance(data, bytes) else str(data)
                replaced = re.sub(
                    parts[1], parts[2], source, count=int(parts[3]), flags=re.MULTILINE
                )
                return replaced.encode("latin-1")
            else:
                print_yellow("Syntax error: please follow this pattern:")
                print_yellow("    r<delimiter><original><delimiter><replacement><delimiter><number_of_replacements>")
                print_yellow("Example:\n    r/GET/HEAD/1 ")
                print_yellow(
                    "Note:\n    Delimiter could be any character you choose. If number_of_replacements is zero, all occurences of original string are replaced.")
                return None

        return None

    def cmd_newdata(self, command, data):
        nd = ''
        nl = 1

        print_yellow_bright(
            "%% Enter new payload line by line (empty line commits). Lines will be sent out separated by CRLF.")
        l = sys.stdin.readline()

        while l not in ("", "\n", "\r\n"):
            nd += l.rstrip("\r\n") + "\r\n"
            nl += 1
            l = sys.stdin.readline()

        if nl > 1:
            print_yellow_bright("%% %d lines (%d bytes)" % (nl, len(nd)))
        else:
            print_yellow_bright("%% empty string - ignored")
        return nd.encode("utf-8")

    def process_command(self, l, mask):

        # print_yellow_bright("# thank you!")

        if l == '':
            l = 'y'

        if l[0] not in mask:
            print_yellow_bright("# Unknown command in this context.")
        else:
            if l.startswith("y"):
                self.send_to_send()

                if self.packet_index == len(self.origins[self.whoami]):
                    print_green_bright("# %s [%d/%d]: that was our last one!!" % (
                        str_time(), self.packet_index, len(self.origins[self.whoami])))

            elif l.startswith('s'):
                self.packet_index += 1
                self.to_send = None
                print_green_bright(
                    "# %s [%d/%d]: has been SKIPPED" % (str_time(), self.packet_index, len(self.origins[self.whoami])))

            elif l.startswith('c'):
                self.to_send = None  # to reinit and ask again
                cnt = self.write(b"\r")
                print_green_bright("# %s custom '\\r' payload (%d bytes) inserted" % (str_time(), cnt,))

            elif l.startswith('l'):
                self.to_send = None  # to reinit and ask again
                cnt = self.write(b"\n")
                print_green_bright("# %s custom '\\n' payload (%d bytes) inserted" % (str_time(), cnt,))

            elif l.startswith('x'):
                self.to_send = None  # to reinit and ask again
                cnt = self.write(b"\r\n")
                print_green_bright("# %s custom '\\r\\n' payload (%d bytes) inserted" % (str_time(), cnt,))

            elif l.startswith('r') or l.startswith('N'):

                ret = None

                if l.startswith('r'):
                    ret = self.cmd_replace(l.strip(), self.to_send)
                elif l.startswith('N'):
                    ret = self.cmd_newdata(l.strip(), self.to_send)

                if ret:
                    self.to_send = ret
                    print_yellow_bright("# %s custom payload created (%d bytes)" % (str_time(), len(self.to_send),))
                    self.ask_to_send(self.to_send)
                else:
                    print_yellow_bright("# Custom payload not created")

            elif l.startswith('i'):
                Features.option_auto_send = (-1 * Features.option_auto_send)
                if Features.option_auto_send > 0:
                    print_yellow_bright("# Toggle automatic send: enabled, interval %d" % (Features.option_auto_send,))
                else:
                    print_yellow_bright("# Toggle automatic send: disabled")

            elif l.startswith('h'):
                self.print_help()

    def print_help(self):
        print_yellow_bright("#    More commands:")
        print_yellow_bright(
            "#    i  - interrupt or continue auto-send feature. Interval=%d." % (abs(Features.option_auto_send),))
        print_yellow_bright("#    r  - replace (vim 's' syntax: r/<orig>/<repl>/<count,0=all>)")
        print_yellow_bright("#       - will try to match on all buffer lines")
        print_yellow_bright("#    N  - prepare brand new data. Multiline, empty line commits. ")

    def init_fuzz(self, args):
        if args.fuzz:
            magic = "pplay"

            if args.fuzz_magic:
                magic = args.fuzz_magic[0]

            Features.fuzz_prng = BytesGenerator(magic, use_hash=hashlib.sha256())
            try:
                Features.fuzz_level = int(args.fuzz[0])

                # normalize
                if Features.fuzz_level > 255:
                    print_red("fuzz-level value too big, using max 255")
                    Features.fuzz_level = 255
                elif Features.fuzz_level < 0:
                    print_red("fuzz-level value is negative, using min 0")
                    Features.fuzz_level = 0

            except ValueError:
                print_red("fuzz-level value supposed to be integer between 0 and 255, using default %d"
                          % Features.fuzz_level)

            self.fuzz = True

    def init_scatter(self, args):
        if args.scatter:
            magic = "pplay"

            if args.scatter_magic:
                magic = args.scatter_magic[0]

            Features.scatter_prng = BytesGenerator(magic, use_hash=hashlib.sha256())
            self.scatter = True


# get string and digest ip and port part for IPv4 and IPv6
def address_pair(ip_port_str):
    col_pos = -1
    last_bracket_pos = -1
    idx = 0
    count = 0
    address_version = 4

    for c in ip_port_str:
        if c == ":":
            col_pos = idx
            count = count + 1
        elif c == "]":
            last_bracket_pos = idx
        idx = idx + 1

    im_ip = ip_port_str[0:col_pos]
    im_port = ip_port_str[col_pos + 1:]
    if count > 1:
        address_version = 6

    if len(im_ip) > 1:
        if im_ip[0] == "[" and im_ip[-1] == "]":
            im_ip = im_ip[1:-1]

    return im_ip, im_port, address_version


def print_ok_err(prefix, cond, true_string="OK", false_string="not present", false_hint=None):
    s = prefix
    if cond:
        print_green(s + ": " + true_string)
    else:
        suff = ''
        if false_hint:
            suff = "    " + false_hint
        print_red(s + ": " + false_string + " " + suff)


def print_version(verbose=False):
    print("")
    print_yellow_bright(title)
    print_yellow_bright(pplay_copyright)
    print("")

    print_green("Supported features:\n")
    print_ok_err("Nice colors in terminal ", Features.have_colorama, false_hint="(python3 -m pip install colorama)")
    print_ok_err("PCAP file reader        ", Features.have_scapy, false_hint="(python3 -m pip install scapy)")
    print_ok_err("builtin SSL stack       ", Features.have_ssl, false_hint="(hmm... python usually comes with ssl module)")
    if Features.have_ssl:
        print_ok_err("TLS server auto cert    ", Features.have_crypto, false_hint="(python3 -m pip install cryptography)")
    print_ok_err("SSH replica execution   ", Features.have_paramiko, false_hint="(python3 -m pip install paramiko)")
    print_ok_err("using remote URL files  ", Features.have_requests, false_hint="(python3 -m pip install requests)")
    print_ok_err("SOCKS proxy for client  ", Features.have_socks, false_hint="(python3 -m pip install pysocks)")
    print_ok_err("SCTP protocol           ", Features.have_sctp, false_hint="(check --help-sctp)")

    print("")


def print_overview():
    print_yellow(
        "\nOverview:\npplay is typically used as 2 running instances, one as a --server, and the other as a --client.")
    print_yellow("Replay data are taken from --pcap file, --smcap file or can be randomly generated with --gencap.")
    print_yellow("You probably want to run two instances with the same replay data on two different hosts.")
    print_yellow("\nFor more options see --help\n")


def main():
    global g_script_module

    parser = argparse.ArgumentParser(
        description=title,
        epilog=" - %s " % (pplay_copyright,))

    schemes_supported = "file,"
    if Features.have_requests:
        schemes_supported += "http(s),"
    schemes_supported = schemes_supported[:-1]

    ds = parser.add_argument_group("Data Sources [%s]" % (schemes_supported,))
    group1 = ds.add_mutually_exclusive_group()
    if Features.have_scapy:
        group1.add_argument('--pcap', nargs=1,
                            help='pcap where the traffic should be read (retransmissions not checked)')

    group1.add_argument('--smcap', nargs=1, help='textual capture taken by smithproxy')
    group1.add_argument('--gencap', nargs=1, help='generate connection data based on passed argument string')

    ds.add_argument('--fuzz', nargs=1, help='specify fuzz level 0-255 to taint loaded data with random bytes. '
                                            'Less means more tainted result.')
    ds.add_argument('--fuzz-magic', nargs=1, help='specify fuzz magic seed to get different random bytes (default: "pplay").')

    ds.add_argument('--scatter', required=False, action='store_true',
                    help='prng stream scattering - split segments into more payloads (noop for datagrams)')

    ds.add_argument('--scatter-magic', required=False, nargs=1,
                    help='prng stream scattering - scatter magic seed (default: "pplay")')

    group1.add_argument('--script', nargs=1,
                        help='load python script previously generated by --export command, '
                             'OR use + to indicate script is embedded into source. See --pack option.')
    ds.add_argument('--script-args', nargs=1, help='pass string to the script args')

    ac = parser.add_argument_group("Actions")
    group2 = ac.add_mutually_exclusive_group()
    group2.add_argument('--client', nargs=1,
                        help='replay client-side of the CONNECTION, connect and send payload to specified '
                             'IP address and port. Use IP:PORT or IP.')
    group2.add_argument('--server', nargs='?',
                        help='listen on port and replay server payload, accept incoming connections. '
                             'Use IP:PORT or PORT')
    group2.add_argument('--list', action='store_true',
                        help='rather than act, show to us list of connections in the specified sniff file')
    group2.add_argument('--export', nargs=1,
                        help='take capture file and export it to python script according CONNECTION parameter')
    group2.add_argument('--pack', nargs=1, help='pack packet data into the script itself. Good for automation.')
    group2.add_argument('--smprint', nargs=1,
                        help='print properties of the connection. Args: sip,sport,dip,dport,proto')

    rc = parser.add_argument_group("Remotes")
    rcgroup = rc.add_mutually_exclusive_group()
    if Features.have_paramiko:
        rcgroup.add_argument('--remote-ssh', nargs=1, help=""" Run itself on remote SSH server. 
        Arguments follow this IP:PORT or IP(with 22 as default SSH port) 
        Note: All local files related options are filtered out. 
        Remote server requires only pure python installed, as all smart stuff is done on the originating host.
        """)
    if Features.have_socks:
        rcgroup.add_argument('--socks', nargs=1,
                             help="""Client will connect via SOCKS proxy. Use IP:PORT, 
                             or IP (1080 is default port)""")

    ac_sniff = parser.add_argument_group("Sniffer file filters (mandatory unless --script is used)")
    ac_sniff.add_argument('--connection', nargs=1,
                          help='replay/export specified connection; use format <src_ip>:<sport>. '
                               'IMPORTANT: it\'s SOURCE based to match unique flow!')

    prot = parser.add_argument_group("Protocol options")
    if Features.have_ssl:
        prot.add_argument('--ssl', required=False, action='store_true',
                          help='toggle this flag to wrap payload to SSL (defaults to library ... default)')

    prot.add_argument('--tcp', required=False, action='store_true',
                      help='toggle to override L3 protocol from file and send payload in TCP')
    prot.add_argument('--udp', required=False, action='store_true',
                      help='toggle to override L3 protocol from file and send payload in UDP')
    prot.add_argument('--sport', required=False, nargs=1, help='Specify source port')

    if Features.have_ssl:
        prot.add_argument('--ssl3', required=False, action='store_true',
                          help='ssl3 ... won\'t be supported by library most likely')
        prot.add_argument('--tls1', required=False, action='store_true', help='use tls 1.0')
        prot.add_argument('--tls1_1', required=False, action='store_true', help='use tls 1.1')
        prot.add_argument('--tls1_2', required=False, action='store_true', help='use tls 1.2')

        try:
            if ssl.HAS_TLSv1_3:
                Features.have_tls13 = True
                prot.add_argument('--tls1_3', required=False, action='store_true',
                                  help='use tls 1.3')
        except AttributeError:
            pass

    prot_ssl = parser.add_argument_group("SSL protocol options")
    if Features.have_ssl:
        prot_ssl = parser.add_argument_group("SSL cipher support")
        prot_ssl.add_argument('--cert', required=False, nargs=1, help='certificate (PEM format) for --server mode')
        prot_ssl.add_argument('--key', required=False, nargs=1,
                              help='key of certificate (PEM format) for --server mode')

        if Features.have_crypto:
            prot_ssl.add_argument('--cakey', required=False, nargs=1, help='use to self-sign server-side '
                                                                           'connections based on received SNI')
            prot_ssl.add_argument('--cacert', required=False, nargs=1, help='signing CA certificate to be used'
                                                                            'in conjunction with --ca-key')

        prot_ssl.add_argument('--cipher', required=False, nargs=1, help='specify ciphers based on openssl cipher list')
        prot_ssl.add_argument('--sni', required=False, nargs=1,
                              help='specify remote server name (SNI extension, client only)')
        prot_ssl.add_argument('--alpn', required=False, nargs=1,
                              help='specify comma-separated next-protocols for ALPN extension (client only)')
        prot_ssl.add_argument('--ecdh_curve', required=False, nargs=1, help='specify ECDH curve name')

    var = parser.add_argument_group("Various")

    auto_group = var.add_mutually_exclusive_group()
    auto_group.add_argument('--noauto', required=False, action='store_true',
                            help='toggle this to confirm each payload to be sent')
    auto_group.add_argument('--auto', nargs='?', required=False, type=float, default=5.0,
                            help='let %(prog)s to send payload automatically each AUTO seconds (default: %(default)s)')

    prot.add_argument('--version', required=False, action='store_true', help='just print version and terminate')
    var.add_argument('--exitoneot', required=False, action='store_true',
                     help='If there is nothing left to send and receive, terminate.')

    var.add_argument('--die-after', nargs=1, required=False,
                     help='Simply bail it out once specified amount of seconds passed.')

    var.add_argument('--exitondiff', required=False, action='store_true',
                     help='print error and exit if unexpected data is received')

    var.add_argument('--nostdin', required=False, action='store_true',
                     help='Don\'t read stdin at all. Good for external scripting. Set automatically on Windows.')
    var.add_argument('--nohex', required=False, action='store_true', help='Don\'t show hexdumps for data to be sent.')
    var.add_argument('--nocolor', required=False, action='store_true', help='Don\'t use colorama.')

    var.add_argument('--verbose', required=False, action='store_true', help='Print out more output.')
    var.add_argument('--debug', required=False, action='store_true', help='Print out debugging info.')

    if Features.have_paramiko:
        rem_ssh = parser.add_argument_group("Remote - SSH")
        rem_ssh.add_argument('--remote-ssh-user', nargs=1,
                             help='SSH user. You can use SSH agent, too (so avoiding this option).')
        rem_ssh.add_argument('--remote-ssh-password', nargs=1,
                             help='SSH password. You can use SSH agent, too (so avoiding this option).')

    if Features.have_sctp:
        prot_sctp = parser.add_argument_group("SCTP options")
        prot_sctp.add_argument("--sctp", required=False, action='store_true',
                               help="Enable SCTP. Ccombine with --udp for datagram service, or --ssl for TLS over SCTP")
    else:
        prot_sctp = parser.add_argument_group("SCTP options (support not found)")
        prot_sctp.add_argument("--help-sctp", required=False, action='store_true', help="how to get sctp support")

    args = parser.parse_args(sys.argv[1:])

    if not Features.have_sctp and args.help_sctp:
        help_sctp()
        exit(1)

    try:
        if __pplay_packed_source__:
            print_red("packed data detected")
            args.script = []
            args.script.append('+')

    except Exception:
        pass

    if args.verbose:
        Features.verbose = True

    if args.debug:
        Features.verbose = True
        Features.debuk = True

    if Features.have_colorama:
        if not args.nocolor:
            colorama.init(autoreset=False, strip=False)
        else:
            Features.have_colorama = False

    if args.version:
        print_version()
        sys.exit(1)

    repeater = None
    if (Features.have_scapy and args.pcap) or args.smcap or args.gencap:

        fnm = ""
        is_local = False

        if args.pcap:
            fnm = args.pcap[0]
        elif args.smcap:
            fnm = args.smcap[0]
        elif args.gencap:
            fnm = args.gencap[0]
        else:
            print_red_bright("it should not end up this way :/")
            sys.exit(255)

        if fnm.startswith("file://"):
            fnm = fnm[len("file://"):]
            is_local = True

        elif fnm.startswith("http://") or fnm.startswith("https://"):
            fnm = http_download_temp(fnm)
        else:
            is_local = True

        if fnm:
            if not os.path.isfile(fnm) and not args.gencap:
                print_red_bright("local file doesn't exist: " + fnm)
                sys.exit(3)

            repeater = Repeater(fnm, "")

    elif args.list:
        pass

    elif args.script or args.export:
        repeater = Repeater(None, "")

    elif Features.have_paramiko and args.remote_ssh:
        # the same as script, but we won't init repeater
        pass
    else:
        print_version()
        print_overview()

        sys.exit(-1)

    if repeater is not None:

        debuk("repeater crated")
        repeater.init_fuzz(args)
        repeater.init_scatter(args)

        if args.tcp:
            repeater.is_udp = False

        if args.udp:
            repeater.is_udp = True

        if Features.have_sctp and args.sctp:
            repeater.is_sctp = True

        if args.ssl:
            if args.udp:
                print_red_bright("No DTLS support in python ssl wrappers, sorry.")
                sys.exit(-1)

            repeater.use_ssl = True

        if args.ssl3:
            repeater.sslv = 3
        if args.tls1:
            repeater.sslv = 4
        if args.tls1_1:
            repeater.sslv = 5
        if args.tls1_2:
            repeater.sslv = 6
        if Features.have_tls13 and args.tls1_3:
            repeater.sslv = 7

        if args.cert:
            repeater.ssl_cert = args.cert[0]

        if args.key:
            repeater.ssl_key = args.key[0]

        if args.cipher:
            repeater.ssl_cipher = ":".join(args.cipher)

        if args.sni:
            repeater.ssl_sni = args.sni[0]

        if args.alpn:
            repeater.ssl_alpn = args.alpn[0].split(',')

        if args.ecdh_curve:
            repeater.ssl_ecdh_curve = args.ecdh_curve[0]

        if Features.have_crypto:
            if args.cacert:
                repeater.ssl_ca_cert = args.cacert[0]

            if args.cakey:
                repeater.ssl_ca_key = args.cakey[0]

    if args.list:
        if args.smcap:
            repeater.list_smcap()
        elif Features.have_scapy and args.pcap:
            repeater.list_pcap(args.verbose)
        elif args.gencap:
            repeater.list_gencap()

        sys.exit(0)

    elif args.smprint:
        if args.smcap:
            pr = None
            if args.smprint:
                pr = args.smprint[0]
                repeater.list_smcap(pr)
                sys.exit(0)

        sys.exit(-1)

    # content is controlled by script
    if args.script:

        if args.script_args:
            repeater.scripter_args = args.script_args[0]

        try:

            if args.script[0] != "+":
                # add current directory into PYTHONPATH
                sys.path.append(os.getcwd())

                # if there is path specified in the script filename, add it to PYTHONPATH too
                if os.path.dirname(args.script[0]) != '':
                    sys.path.append(os.path.dirname(args.script[0]))

                print_white_bright("Loading custom script: %s (pwd=%s)" % (args.script[0], os.getcwd()))

                script_path = os.path.abspath(args.script[0])
                module_name = "pplay_script_%s" % hashlib.sha1(
                    script_path.encode("utf-8")
                ).hexdigest()
                spec = importlib.util.spec_from_file_location(module_name, script_path)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot create module spec for %s" % script_path)
                g_script_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(g_script_module)

                repeater.scripter = g_script_module.PPlayScript(repeater, repeater.scripter_args)
                repeater.load_scripter_defaults()
            else:
                repeater.scripter = PPlayScript(repeater, repeater.scripter_args)
                repeater.load_scripter_defaults()

            if repeater.fuzz:
                debuk("refuzzing traffic")
                repeater.scripter_refuzz()

        except ImportError as e:
            print_red_bright("Error loading script file: %s" % (str(e),))
            sys.exit(-2)
        except AttributeError as e:
            print_red_bright("Error loading script file: %s" % (str(e),))
            sys.exit(-2)

    if args.export or args.pack or args.client or args.server:

        # attempt
        if (Features.have_scapy and args.pcap) and not args.connection:
            candidate = repeater.list_pcap(False, do_print=False)
            if not candidate:
                print_white_bright("--connection argument has to be set with your data (cannot guess first usable flow)")
                sys.exit(-1)
            else:
                print_green_bright("first usable connection selected: " + candidate)
                args.connection = [candidate, ]

        if args.gencap:
            args.connection = ["autogenerated", ]

        if args.connection:

            # find port separator, last :
            # Note: split cannot be used, since we have concatenated IPv6 notation which would break
            # by splitting by ":" and joining back

            im_ip, im_port, im_ver = address_pair(args.connection[0])

            if args.verbose:
                print("Using connection: " + im_ip + ":" + im_port + " : version " + str(im_ver))

            if args.smcap:
                repeater.read_smcap(im_ip, im_port)
            elif Features.have_scapy and args.pcap:
                repeater.read_pcap(im_ip, im_port)
            elif args.gencap:
                repeater.read_gencap(im_ip, im_port)

            if not len(repeater.packets):
                hint = "\n no data extracted: check capture file"
                if args.pcap:
                    hint += " and connection id"
                print_red_bright(hint + "\n")
                sys.exit(3)

            if args.tcp:
                repeater.is_udp = False
            elif args.udp:
                repeater.is_udp = True

        elif args.smcap:
            # no --connection option setsockopt

            # okay, smcap holds only single connection
            # detect and read the connection

            ip_port = repeater.list_smcap().split(":")
            if len(ip_port) > 1:
                im_ip = ip_port[0]
                im_port = ip_port[1]
                repeater.read_smcap(im_ip, im_port)

        # cannot collide with script - those are in the exclusive argparse group
        if args.export:

            if args.cert:
                repeater.ssl_cert = args.cert[0]

            if args.key:
                repeater.ssl_key = args.key[0]

            if Features.have_crypto:
                if args.cacert:
                    repeater.ssl_ca_cert = args.cacert[0]

                if args.cakey:
                    repeater.ssl_ca_key = args.cakey[0]

            export_file = args.export[0]
            if repeater.export_script(export_file):
                print_white_bright("Template python script has been exported to file %s" % (export_file,))
            sys.exit(0)

        elif args.pack:
            pack_file = args.pack[0]

            if args.cert:
                repeater.ssl_cert = args.cert[0]

            if args.key:
                repeater.ssl_key = args.key[0]

            if Features.have_crypto:
                if args.cacert:
                    repeater.ssl_ca_cert = args.cacert[0]

                if args.cakey:
                    repeater.ssl_ca_key = args.cakey[0]

            repeater.export_self(pack_file)
            print_white_bright("Exporting self to file %s" % (pack_file,))
            sys.exit(0)

        # ok regardless data controlled by script or capture file read
        elif args.client or args.server:

            if Features.have_paramiko:
                if args.remote_ssh:

                    port = "22"
                    host = "127.0.0.1"
                    host_port = args.remote_ssh[0].split(":")

                    if len(host_port) > 0:
                        host = host_port[0]
                        if not host:
                            host = "127.0.0.1"

                    if len(host_port) > 1:
                        port = host_port[1]

                    print_white("remote location: %s:%s" % (host, port,))

                    # this have_ is local only!
                    have_script = False
                    my_source = None
                    try:
                        if __pplay_packed_source__:
                            print_white_bright("remote-ssh[this host] - having embedded PPlayScript")
                            have_script = True

                            # it's not greatest way to get this script source, but as long as pplay is 
                            # single-source python script, it will work. Otherwise, we will need to do quine
                            my_source = open(__file__).read()

                    except NameError as e:
                        have_script = False
                        # print_red_bright("!!! this source is not produced by --pack,
                        # all required files must be available on your remote!")

                    if not have_script:

                        print_white_bright(
                            "remote-ssh[this host] - packing to tempfile (you need all arguments for --pack)")

                        if args.cert:
                            repeater.ssl_cert = args.cert[0]

                        if args.key:
                            repeater.ssl_key = args.key[0]

                        if Features.have_crypto:
                            if args.cacert:
                                repeater.ssl_ca_cert = args.cacert[0]

                            if args.cakey:
                                repeater.ssl_ca_key = args.cakey[0]

                        temp_file = tempfile.NamedTemporaryFile(prefix="pplay", suffix="packed")
                        repeater.export_self(temp_file.name)
                        print_white_bright("remote-ssh[this host] - done")
                        my_source = open(temp_file.name).read()

                        have_script = True

                    if my_source:

                        client = None
                        stdout = None
                        remote_status = None
                        remote_error = None
                        try:
                            paramiko.util.log_to_file('/dev/null')
                            from paramiko.ssh_exception import SSHException, AuthenticationException

                            client = paramiko.SSHClient()
                            client.load_system_host_keys()
                            # client.set_missing_host_key_policy(paramiko.WarningPolicy)
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                            if args.remote_ssh_user and args.remote_ssh_password:
                                client.connect(hostname=host, port=int(port), username=args.remote_ssh_user[0],
                                               password=args.remote_ssh_password[0], allow_agent=False,
                                               look_for_keys=False)
                                chan = client.get_transport().open_session(timeout=10)

                            elif args.remote_ssh_user:
                                client.connect(hostname=host, port=int(port), username=args.remote_ssh_user[0])
                                chan = client.get_transport().open_session(timeout=10)

                                paramiko.agent.AgentRequestHandler(chan)
                            else:
                                client.connect(hostname=host, port=int(port))
                                chan = client.get_transport().open_session(timeout=10)

                                paramiko.agent.AgentRequestHandler(chan)

                            cmd = "python3 -u - "
                            if have_script:
                                cmd += "--script +"

                            # iterate args and filter unwanted remote arguments, because of this we are not allowing
                            # abbreviated options :(

                            filter_next = False
                            for arg in sys.argv[1:]:
                                if filter_next:
                                    filter_next = False
                                    continue

                                if arg.startswith("--remote") or arg.startswith("--smcap") or arg.startswith("--pcap") \
                                        or arg.startswith("--key") or arg.startswith("--cert") \
                                        or arg.startswith("--cakey") or arg.startswith("--cacert") \
                                        or arg.startswith("--gencap"):
                                    filter_next = True
                                    continue

                                cmd += " " + shlex.quote(arg)

                            # don't monitor stdin (it's always readable over SSH)
                            # exit on the end of replay transmission --remote-ssh is intended to one-shot tests anyway
                            cmd += " --nostdin"

                            # FIXME: not sure about this. Don't assume what user really wants to do
                            # cmd += " --exitoneot"

                            debuk("sending cmd: " + cmd)

                            #
                            # chan.set_environment_variable(name="PPLAY_COLORAMA",value="1")
                            chan.set_combine_stderr(True)
                            chan.exec_command(cmd)
                            stdin = chan.makefile("wb", 10240)
                            stdout = chan.makefile("r", 10240)
                            # stderr = chan.makefile_stderr("r", 1024)

                            # write myself (worm-like!)
                            stdin.write(my_source)
                            stdin.flush()
                            # we must shutdown, so remote python knows the script is complete
                            chan.shutdown_write()

                            print_red("--- REMOTE OUTPUT START ---")

                            while not chan.exit_status_ready():
                                time.sleep(0.1)
                                if chan.recv_ready():
                                    d = chan.recv(10240)
                                    if len(d) > 0:
                                        sys.stdout.write(bytes(d).decode('utf-8'))

                                r, w, e = select([sys.stdin, ], [], [], repeater.select_timeout)
                                if sys.stdin in r:
                                    cmd = sys.stdin.readline()

                                    # print_red("cmd: " + cmd + "<<")
                                    # this currently doesn't work - stdin is closed by channel                                
                                    stdin.write(cmd)

                            while chan.recv_ready():
                                d = chan.recv(10240)
                                if len(d) > 0:
                                    sys.stdout.write(bytes(d).decode('utf-8'))

                            remote_status = chan.recv_exit_status()

                        except paramiko.AuthenticationException as e:
                            remote_error = e
                            print_red_bright("remote-ssh[local]: authentication failed: %s" % e)

                        except paramiko.SSHException as e:
                            remote_error = e
                            print_red_bright("remote-ssh[local]: ssh protocol error: %s" % e)

                        except KeyboardInterrupt as e:
                            print_red_bright("remote-ssh[local]: Ctrl-C: bailing, terminating remote-ssh.")

                        except socket.error as e:
                            remote_error = e
                            print_red_bright("remote-ssh[local]: socket error: %s" % e)
                        finally:
                            if client:
                                client.close()

                        print_red("--- REMOTE OUTPUT END ---")

                        if stdout:
                            stdout.flush()

                        if remote_error is not None:
                            sys.exit(2)

                        if remote_status:
                            print_red_bright("remote-ssh[remote]: command failed with status %d" % remote_status)
                            sys.exit(remote_status)

                        sys.exit(0)
                    else:
                        print_red_bright("paramiko unavailable or --pack failed")

            if Features.have_socks and args.socks:
                # print_red("Will use SOCKS") # DEBUG
                Features.option_socks = args.socks[0].split(":")

            if args.ssl:
                if not Features.have_ssl:
                    print_red_bright("error: SSL not available!")
                    sys.exit(-1)

                if args.server:
                    if not (
                            (args.key and args.cert)
                            or
                            (args.cakey and args.cacert)
                    ) and not args.script:
                        print_red_bright("error: SSL server requires: \n"
                                         "      --key and --cert for exact server certificate\n"
                                         "   -or- \n"
                                         "      --cakey and --cacert argument for generated certs by CA\n")
                        sys.exit(-1)

                repeater.use_ssl = True

            if args.noauto:
                Features.option_auto_send = -1
            elif args.auto:
                Features.option_auto_send = args.auto

            else:
                # Features.option_auto_send = 5
                pass

            if args.nostdin:
                print_red_bright("stdin will be unmonitored")
                repeater.nostdin = True

            if args.nohex:
                repeater.nohexdump = True

            if args.exitoneot:
                repeater.exitoneot = True

            if args.exitondiff:
                repeater.exitondiff = True

            if args.udp:
                if len(repeater.origins['server']) > 0 and repeater.origins['server'][0] == 0:
                    print_red_bright("datagram connection cannot start sending data from server")
                    sys.exit(-1)

            if args.client:

                if args.sport:
                    repeater.custom_sport = args.sport[0]

                if len(args.client) > 0:
                    repeater.custom_ip = args.client[0]

                if args.die_after:
                    repeater.die_after = int(args.die_after[0])

                repeater.impersonate('client')

            elif args.server:

                if args.die_after:
                    repeater.die_after = int(args.die_after[0])

                if len(args.server) > 0:
                    # arg type is '?' so no list there, just string
                    repeater.custom_ip = args.server
                else:
                    repeater.custom_ip = None

                repeater.impersonate('server')

    else:
        print_white_bright("No-op!")
        print_overview()


def cleanup():
    global g_delete_files
    for f in g_delete_files:
        try:
            debuk("unlink tempfile - %s" % (f,))
            os.unlink(f)
        except OSError as e:
            pass

    g_delete_files.clear()


if __name__ == "__main__":
    atexit.register(cleanup)

    try:
        main()
    except socket.error as e:
        print_red("socket error: " + str(e))
