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
    sans = [f'DNS:{hostname}']
    # The routing suite deliberately rewrites client.example to this origin
    # identity. Keep that test about routing/SNI, not an unrelated certificate
    # mismatch which fail-close correctly rejects.
    if name == 'origin':
        sans.extend(('DNS:origin.internal', 'DNS:other.example'))
    ext.write_text(f'subjectAltName={",".join(sans)}\nbasicConstraints=CA:FALSE\n')
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
# The base dataplane probes isolate MITM trust and transport behavior. Their
# disposable origin certificate intentionally has neither public SCTs nor an
# OCSP responder; dedicated TLS tests cover those policies separately.
text, lab_ocsp_count = re.subn(
    r'(tls_profiles\s*=\s*\{\s*default\s*=\s*\{.*?ocsp_stapling\s*=\s*)TRUE',
    r'\g<1>FALSE', text, count=1, flags=re.DOTALL,
)
text, lab_ct_count = re.subn(
    r'(tls_profiles\s*=\s*\{\s*default\s*=\s*\{)',
    r'\1\n        ct_enable = FALSE;', text, count=1,
)
if lab_ocsp_count != 1 or lab_ct_count != 1:
    raise RuntimeError('cannot isolate base lab TLS profile from CT/OCSP checks')
tls_write_chunk = os.environ.get('TLS_WRITE_CHUNK')
if tls_write_chunk is not None:
    if not tls_write_chunk.isdigit() or not 1024 <= int(tls_write_chunk) <= 1048576:
        raise ValueError('TLS_WRITE_CHUNK must be between 1024 and 1048576')
    text = text.replace('settings = {', f'''settings = {{
    tuning = {{ tls_write_chunk = {tls_write_chunk}; }};
''', 1)
ssl_use_ktls = os.environ.get('SSL_USE_KTLS')
if ssl_use_ktls is not None:
    if ssl_use_ktls not in ('0', '1'):
        raise ValueError('SSL_USE_KTLS must be 0 or 1')
    enabled = 'TRUE' if ssl_use_ktls == '1' else 'FALSE'
    text = text.replace('settings = {', f'''settings = {{
    ssl_use_ktls = {enabled};
''', 1)
quic_test = os.environ.get('QUIC_TEST') == '1'
if os.environ.get('POLICY_TEST') == '1':
    policy_address_objects = '''
    test_nonmatching4 = { type = 0; cidr = "203.0.113.254/32"; };
    test_nonmatching6 = { type = 0; cidr = "2001:db8:ffff::1/128"; };
'''
    text, address_count = re.subn(r'(address_objects\s*=\s*\{)', r'\1\n' + policy_address_objects, text, count=1)
    port_objects = '''
    test_9989 = { start = 9989; end = 9989; };
    test_9990 = { start = 9990; end = 9990; };
    test_9991 = { start = 9991; end = 9991; };
    test_9992 = { start = 9992; end = 9992; };
    test_9993 = { start = 9993; end = 9993; };
    test_9994 = { start = 9994; end = 9994; };
    test_9996 = { start = 9996; end = 9996; };
    test_9997 = { start = 9997; end = 9997; };
    test_9998 = { start = 9998; end = 9998; };
    test_9995 = { start = 9995; end = 9995; };
'''
    text, port_count = re.subn(r'(port_objects\s*=\s*\{)', r'\1\n' + port_objects, text, count=1)
    policy_cases = '''
    { name = "test-missing-tls-profile-must-disable"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9989" ]; tls_profile = "definitely_missing_runner_tls"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-after-missing-profile-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9989" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-precedence-first-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9994" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-precedence-late-accept"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9994" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { disabled = TRUE; name = "test-disabled-accept"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9993" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-after-disabled-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9993" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-protocol-mismatch-udp-deny"; proto = "udp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9992" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-protocol-match-tcp-accept"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9992" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-port-mismatch-accept"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9992" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-after-port-mismatch-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9991" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-source-mismatch4-accept"; proto = "tcp"; src = [ "test_nonmatching4" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9990" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-after-source-mismatch4-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9990" ]; action = "deny"; nat = "none"; routing = "none"; },
    { disabled = TRUE; name = "test-disabled-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9998" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-named-accept-profile"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9996" ]; detection_profile = "detect"; content_profile = "default"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test-named-deny"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9997" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test-legacy-reject-alias"; proto = "tcp"; src = [ "any" ]; sport = [ "all" ]; dst = [ "any" ]; dport = [ "test_9995" ]; action = "reject"; nat = "none"; routing = "none"; },
    { disabled = TRUE; name = "test6-disabled-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9998" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-named-accept-profile"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9996" ]; detection_profile = "detect"; content_profile = "default"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-named-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9997" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-legacy-reject-alias"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9995" ]; action = "reject"; nat = "none"; routing = "none"; },
    { name = "test6-precedence-first-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9994" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-precedence-late-accept"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9994" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { disabled = TRUE; name = "test6-disabled-accept"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9993" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-after-disabled-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9993" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-protocol-mismatch-udp-deny"; proto = "udp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9992" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-protocol-match-tcp-accept"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9992" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-port-mismatch-accept"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9992" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-after-port-mismatch-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9991" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-source-mismatch-accept"; proto = "tcp"; src = [ "test_nonmatching6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9990" ]; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-after-source-mismatch-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9990" ]; action = "deny"; nat = "none"; routing = "none"; },
    { name = "test6-missing-tls-profile-must-disable"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9989" ]; tls_profile = "definitely_missing_runner_tls"; action = "accept"; nat = "auto"; routing = "none"; },
    { name = "test6-after-missing-profile-deny"; proto = "tcp"; src = [ "any6" ]; sport = [ "all" ]; dst = [ "any6" ]; dport = [ "test_9989" ]; action = "deny"; nat = "none"; routing = "none"; },
'''
    text, count = re.subn(r'(policy\s*=\s*\()', r'\1\n' + policy_cases, text, count=1)
    if address_count != 1 or port_count != 1 or count != 1: raise RuntimeError('cannot inject policy suite objects/rules')
if quic_test:
    if os.environ.get('QUIC_LAB') != '1':
        raise RuntimeError('QUIC_TEST requires QUIC_LAB=1')
    text, port_count = re.subn(
        r'(port_objects\s*=\s*\{)',
        r'\1\n    quic_runner_443 = { start = 443; end = 443; };',
        text, count=1,
    )
    profile = '''
    quic_runner = {
        write_payload = TRUE;
        write_format = "pcap_single";
        write_limit_client = 0;
        write_limit_server = 0;
    }
'''
    text, profile_count = re.subn(
        r'(content_profiles\s*=\s*\{)', r'\1\n' + profile,
        text, count=1,
    )
    rule = '''
    {
        name = "runner-quic-udp-capture";
        proto = "udp";
        src = [ "any" ];
        sport = [ "all" ];
        dst = [ "any" ];
        dport = [ "quic_runner_443" ];
        tls_profile = "default";
        detection_profile = "detect";
        content_profile = "quic_runner";
        action = "accept";
        nat = "auto";
        routing = "none";
    },
'''
    text, policy_count = re.subn(
        r'(policy\s*=\s*\()', r'\1\n' + rule,
        text, count=1,
    )
    if port_count != 1 or profile_count != 1 or policy_count != 1:
        raise RuntimeError('cannot inject QUIC runner policy and capture profile')

if os.environ.get('ROUTING_TEST') == '1':
    address_objects = '''
    route_backend4_a = { type = 0; cidr = "198.18.20.2/32"; };
    route_backend4_b = { type = 0; cidr = "198.18.20.3/32"; };
    route_backend6_a = { type = 0; cidr = "fd00:20::2/128"; };
    route_backend6_b = { type = 0; cidr = "fd00:20::3/128"; };
'''
    text, address_count = re.subn(r'(address_objects\s*=\s*\{)', r'\1\n' + address_objects, text, count=1)
    port_objects = '''
    route_backend_18080 = { start = 18080; end = 18080; };
    route_backend_18081 = { start = 18081; end = 18081; };
    route_req_address = { start = 19080; end = 19080; };
    route_req_port = { start = 19081; end = 19081; };
    route_req_rr = { start = 19082; end = 19082; };
    route_req_l3 = { start = 19083; end = 19083; };
    route_req_l4 = { start = 19100; end = 19115; };
    route_req_socks = { start = 19200; end = 19200; };
    route_req_connect = { start = 19300; end = 19300; };
    route_req_sni = { start = 19443; end = 19443; };
    route_backend_18443 = { start = 18443; end = 18443; };
'''
    text, port_count = re.subn(r'(port_objects\s*=\s*\{)', r'\1\n' + port_objects, text, count=1)
    routing_profiles = '''
    test_address = { dnat_address = [ "route_backend4_a", "route_backend6_a" ]; dnat_port = [ ]; dnat_lb_method = "round-robin"; };
    test_port = { dnat_address = [ ]; dnat_port = [ "route_backend_18080" ]; dnat_lb_method = "round-robin"; };
    test_rr = { dnat_address = [ "route_backend4_a", "route_backend4_b", "route_backend6_a", "route_backend6_b" ]; dnat_port = [ "route_backend_18080" ]; dnat_lb_method = "round-robin"; };
    test_l3 = { dnat_address = [ "route_backend4_a", "route_backend4_b", "route_backend6_a", "route_backend6_b" ]; dnat_port = [ "route_backend_18080" ]; dnat_lb_method = "sticky-l3"; };
    test_l4 = { dnat_address = [ "route_backend4_a", "route_backend4_b", "route_backend6_a", "route_backend6_b" ]; dnat_port = [ "route_backend_18080" ]; dnat_lb_method = "sticky-l4"; };
    test_socks = { dnat_address = [ "route_backend4_a", "route_backend6_a" ]; dnat_port = [ "route_backend_18080" ]; dnat_lb_method = "round-robin"; };
    test_connect = { dnat_address = [ "route_backend4_a", "route_backend6_a" ]; dnat_port = [ "route_backend_18081" ]; dnat_lb_method = "round-robin"; };
    test_sni = { dnat_address = [ "route_backend4_a", "route_backend6_a" ]; dnat_port = [ "route_backend_18443" ]; dnat_lb_method = "round-robin"; rewrite_sni = "client.example"; rewrite_sni_to = "origin.internal"; };
'''
    text, routing_count = re.subn(r'(routing\s*=\s*\{)', r'\1\n' + routing_profiles, text, count=1)
    routing_policies = '''
    { name = "test-route-address"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_address" ]; action = "accept"; nat = "auto"; routing = "test_address"; },
    { name = "test-route-port"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_port" ]; action = "accept"; nat = "auto"; routing = "test_port"; },
    { name = "test-route-rr"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_rr" ]; action = "accept"; nat = "auto"; routing = "test_rr"; },
    { name = "test-route-l3"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_l3" ]; action = "accept"; nat = "auto"; routing = "test_l3"; },
    { name = "test-route-l4"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_l4" ]; action = "accept"; nat = "auto"; routing = "test_l4"; },
    { name = "test-route-socks"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_socks" ]; action = "accept"; nat = "auto"; routing = "test_socks"; },
    { name = "test-route-connect"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_connect" ]; action = "accept"; nat = "auto"; routing = "test_connect"; },
    { name = "test-route-sni"; proto = "tcp"; src = [ "any", "any6" ]; sport = [ "all" ]; dst = [ "any", "any6" ]; dport = [ "route_req_sni" ]; tls_profile = "default"; action = "accept"; nat = "auto"; routing = "test_sni"; },
'''
    text, policy_count = re.subn(r'(policy\s*=\s*\()', r'\1\n' + routing_policies, text, count=1)
    if (address_count, port_count, routing_count, policy_count) != (1, 1, 1, 1):
        raise RuntimeError('cannot inject routing suite objects/profiles/rules')
text = text.replace('/etc/smithproxy/certs/default/',str(certs)+'/').replace('/etc/smithproxy/msg/en/',str(source/'etc/msg/en')+'/')
text = text.replace('/var/smithproxy/data',str(data)).replace('/var/log/smithproxy/',str(data)+'/')
text = text.replace('certs_ca_key_password = "smithproxy"','certs_ca_key_password = ""')
text = text.replace('accept_redirect = TRUE','accept_redirect = FALSE').replace('accept_socks = TRUE','accept_socks = FALSE')
if os.environ.get('TLS_EVASION_TRACE') == '1':
    # The shipped configuration has existed with and without a trailing
    # semicolon. Match the stable assignment itself so trace mode cannot
    # silently leave the ordinary INFO level enabled.
    text, trace_level_count = re.subn(r'log_level\s*=\s*6', 'log_level = 9', text, count=1)
    if trace_level_count != 1:
        raise RuntimeError('cannot enable trace log level in generated configuration')
    text, trace_component_count = re.subn(
        r'(?m)^(\s*)//proxy\s*=\s*\d+;',
        r'\1proxy = 10;\n\1epoll = 10;', text, count=1)
    if trace_component_count != 1:
        raise RuntimeError('cannot enable proxy/epoll component trace levels')
if os.environ.get('ROUTING_TEST') == '1':
    text = text.replace('accept_socks = FALSE', 'accept_socks = TRUE')
text = re.sub(r'(plaintext_workers|ssl_workers|udp_workers) = 0',r'\1 = 1',text)
# Keep one lab lightweight enough for deliberate high-concurrency runs.  DTLS
# has a hardware-concurrency default even though the sample config omits the
# key; without an explicit override P16 creates hundreds of idle listeners.
if 'dtls_workers' not in text:
    text = text.replace('ssl_workers = 1;', 'ssl_workers = 1;\n    dtls_workers = 1;', 1)
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
        r'(remote\s*=\s*\{\s*enabled\s*=\s*)false'
        r'([^{}]*?tun_type\s*=\s*"gre"[^{}]*?tun_dst\s*=\s*)"[^"]+"',
        rf'\g<1>true\g<2>"{gre_capture_dst}"', text, count=1, flags=re.IGNORECASE,
    )
    content_count = 1
    if not quic_test:
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
