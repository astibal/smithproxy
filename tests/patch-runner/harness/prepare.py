#!/usr/bin/env python3
"""Generate isolated lab config and disposable certificates, without editing upstream."""
import os, pathlib, re, secrets, subprocess, sys

# Private keys and the API key must never be created world-readable.
os.umask(0o077)
root = pathlib.Path(sys.argv[1]).resolve()
source = root / 'src'
config = root / 'config'
data = root / 'data'
certs = config / 'certs'
certs.mkdir(parents=True, exist_ok=True)
data.mkdir(exist_ok=True)
def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Runner Test CA', '-keyout', certs/'ca-key.pem', '-out', certs/'ca-cert.pem', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
# A separate origin CA proves that the client received a forged proxy certificate.
openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Runner Origin CA', '-keyout', certs/'origin-ca-key.pem', '-out', certs/'origin-ca.pem', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
for name, hostname, ca in [('srv','runner.lab','ca'), ('cl','runner.lab','ca'), ('portal','localhost','ca'), ('origin','origin.runner.lab','origin-ca')]:
    openssl('req','-new','-newkey','rsa:2048','-nodes','-subj',f'/CN={hostname}', '-keyout',certs/f'{name}-key.pem','-out',certs/f'{name}.csr')
    ext = certs / f'{name}.ext'
    ext.write_text(f'subjectAltName=DNS:{hostname}\nbasicConstraints=CA:FALSE\n')
    ca_cert = 'ca-cert.pem' if ca == 'ca' else 'origin-ca.pem'
    openssl('x509','-req','-in',certs/f'{name}.csr','-CA',certs/ca_cert,'-CAkey',certs/f'{ca}-key.pem','-CAcreateserial','-days','2','-extfile',ext,'-out',certs/f'{name}-cert.pem')
    (certs/f'{name}-key.pem').chmod(0o600)
for name in ('ca-key.pem','origin-ca-key.pem'):
    (certs/name).chmod(0o600)
api_key = secrets.token_hex(32)
(config/'api.key').write_text(api_key + '\n')
internal_api_port = os.environ.get('SMITHPROXY_API_PORT', '55555')
if not internal_api_port.isdigit() or not 1025 <= int(internal_api_port) < 65535:
    raise ValueError('SMITHPROXY_API_PORT must be an unprivileged TCP port')
text = (source/'etc/smithproxy.cfg').read_text()
if os.environ.get('POLICY_TEST') == '1':
    port_objects = '''
    test_9996 = { start = 9996; end = 9996; };
    test_9997 = { start = 9997; end = 9997; };
    test_9998 = { start = 9998; end = 9998; };
    test_9995 = { start = 9995; end = 9995; };
'''
    text, port_count = re.subn(r'(port_objects\s*=\s*\{)', r'\1\n' + port_objects, text, count=1)
    policy_cases = '''
    { disabled = TRUE; name = "test-disabled-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9998" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-named-accept-profile"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9996" ]; detection_profile = "detect"; content_profile = "default"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-named-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9997" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-legacy-reject-alias"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9995" ]; action = "reject"; nat = "none"; routing = "none"; },
    { disabled = TRUE; name = "test6-disabled-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9998" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-named-accept-profile"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9996" ]; detection_profile = "detect"; content_profile = "default"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-named-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9997" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-legacy-reject-alias"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9995" ]; action = "reject"; nat = "none"; routing = "none"; },
'''
    text, count = re.subn(r'(policy\s*=\s*\()', r'\1\n' + policy_cases, text, count=1)
    if port_count != 1 or count != 1: raise RuntimeError('cannot inject policy suite objects/rules')
text = text.replace('/etc/smithproxy/certs/default/',str(certs)+'/').replace('/etc/smithproxy/msg/en/',str(source/'etc/msg/en')+'/')
text = text.replace('/var/smithproxy/data',str(data)).replace('/var/log/smithproxy/',str(data)+'/')
text = text.replace('certs_ca_key_password = "smithproxy"','certs_ca_key_password = ""')
text = text.replace('accept_redirect = TRUE','accept_redirect = FALSE').replace('accept_socks = TRUE','accept_socks = FALSE')
text = re.sub(r'(plaintext_workers|ssl_workers|udp_workers) = 0',r'\1 = 1',text)
if os.environ.get('QUIC_LAB') == '1':
    # QUIC has no main-thread fallback: zero workers leaves the configured
    # port without a listener. Keep the isolated H3 lab deterministic with a
    # single worker; production deployments can scale this independently.
    text = text.replace('quic_workers = -1', 'quic_workers = 1')
text = re.sub(r'\s*auth_profile = "resolve";', '', text)
text = text.replace('nameservers = [ "8.8.8.8", "8.8.4.4" ]','nameservers = [ "198.18.20.2" ]')
gre_capture_dst = os.environ.get('GRE_CAPTURE_DST')
if gre_capture_dst:
    if not re.fullmatch(r'[0-9A-Fa-f:.]+', gre_capture_dst):
        raise ValueError('GRE_CAPTURE_DST must be an IP address')
    text, remote_count = re.subn(
        r'(remote\s*=\s*\{\s*enabled\s*=\s*)false(\s*tun_type\s*=\s*"gre"\s*tun_dst\s*=\s*)"[^"]+"',
        rf'\g<1>true\g<2>"{gre_capture_dst}"', text, count=1, flags=re.IGNORECASE,
    )
    text, content_count = re.subn(
        r'(content_profiles\s*=\s*\{\s*default\s*=\s*\{\s*write_payload\s*=\s*)FALSE',
        r'\g<1>TRUE', text, count=1, flags=re.IGNORECASE,
    )
    checksum_count = udp_profile_count = 1
    if os.environ.get('CAPTURE_CALCULATE_CHECKSUMS') == '1':
        text, checksum_count = re.subn(
            r'(tun_ttl\s*=\s*\d+\s*\n\s*\})(\s*\n\})',
            r'\g<1>\n  options =\n  {\n    calculate_checksums = true\n  }\g<2>',
            text, count=1, flags=re.IGNORECASE,
        )
    if os.environ.get('CAPTURE_UDP_CONTENT_PROFILE') == '1':
        text, udp_profile_count = re.subn(
            r'(proto\s*=\s*"udp";.*?dport\s*=\s*\[\s*"all"\s*\];)',
            r'\g<1>\n        detection_profile = "detect";\n        content_profile = "default";',
            text, count=1, flags=re.IGNORECASE | re.DOTALL,
        )
    if remote_count != 1 or content_count != 1 or checksum_count != 1 or udp_profile_count != 1:
        raise RuntimeError('cannot enable GRE capture in generated config')
capture_prefix = os.environ.get('CAPTURE_FILE_PREFIX')
if capture_prefix:
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', capture_prefix):
        raise ValueError('CAPTURE_FILE_PREFIX contains unsafe characters')
    text, prefix_count = re.subn(
        r'(captures\s*=\s*\{\s*local\s*=\s*\{.*?file_prefix\s*=\s*)"[^"]*"',
        rf'\g<1>"{capture_prefix}"', text, count=1, flags=re.IGNORECASE | re.DOTALL,
    )
    if prefix_count != 1:
        raise RuntimeError('cannot set capture prefix in generated config')
text = text.replace('settings = {', f'''settings = {{
    accept_api = TRUE;
    ca_bundle_file = "{certs / 'origin-ca.pem'}";
    http_api = {{
        keys = [ "{api_key}" ];
        loopback_only = TRUE;
        allow_api_header = TRUE;
        port = {internal_api_port};
    }};
''', 1)
(config/'smithproxy.cfg').write_text(text)
input_if = os.environ.get('LAB_IN_IF', 'di0')
(config/'network.conf').write_text(f'''INPUT_CIDRS[{input_if}]=198.18.10.1/24
INPUT_CIDRS6[{input_if}]=fd00:10::1/64
OUT_CIDR=198.18.20.1/24
GATEWAY=198.18.20.2
OUT_CIDR6=fd00:20::1/64
GATEWAY6=fd00:20::2
API_BIND=127.0.0.1
API_PORT=55556
''')
print('Lab configuration and certificates prepared:', config)
