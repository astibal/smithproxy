# Installing Smithproxy from binary .deb packages (stable)

# Foreword
This doc is by far not complete and it even is not supposed to be. It's quick-start with some commentary. You don't need to read paragraphs with horizontal lines. They are giving background information not necessary to comprehend to install smithproxy.

# Installation script 


Before of installing anything - refresh APT - it's always good idea, right?

```
sudo apt update
```

Now run this script. You can paste it all to shell, it will do the work. As of time of the writing of this howto, script is basically a bit touched Dockerfile for ubuntu docker image. You can see it online here, in my [bitbucket 0.8 repository](https://bitbucket.org/astibal/smithproxy/src/0.8/tools/docker/Dockerfile-ubuntu18.04-run) ... and maybe update it to your liking. 
```
echo "=== installing bootstrapping tools" && \
apt update && apt install -y \
wget \
python-pip dnsutils wget dnsutils

echo "=== installing dependecies"; \
apt install -y libcli1.9 libconfig++9v5 libssl1.0.0 libunwind8 python-pip && \
apt install -y iptables python-ldap python-pyparsing python-posix-ipc python-soappy python-m2crypto telnet iproute2 && \
apt install -y python3 python3-pip python3-cryptography python3-pyroute2

echo "=== Getting latest stable package names from DNS"; \
SX1=`dig +short latest.ubuntu1804.deb.smithproxy.org TXT | tr -d '"'` ; echo "marked for download: $SX1"; \
SX2=`dig +short latest-pylibconfig2.ubuntu1804.deb.smithproxy.org TXT | tr -d '"'`; echo "marked for download: $SX2"; \
wget $SX2 && dpkg -i `basename $SX2` && \
wget $SX1 && dpkg -i `basename $SX1` && \
echo "=== remove unneeded packages"; \
apt remove -y g++ gcc perl manpages && apt -y autoremove

```
> How does it work? It will install all base tools and dependencies. I am using DNS for newest package versions naming `latest.ubuntu1804.deb.smithproxy.org` will  then always resolve in freshest smithproxy .deb package URL for (in this example) Ubuntu 18.04.

# Configuration

Smithproxy is not that simple software. You need to configure it properly, before really using it:

### Networking
If not done yet, please finalize your network environment. Configure linux interfaces as intended. Ideal is  to have:

* external interface name (ie. ens0)
* internal interface name (ie. ens5) -- all connections received here will be intercepted

Now open configuration file `/etc/smithproxy/smithproxy.startup.cfg`, and change `SMITH_INTERFACE` variable to your *internal* interface name. This is interface, where almost all *routed* traffic will be inspected (meaning redirected to tproxy and processed by smithproxy). You can also have a look on other options and change them to your liking.

For my appliance it looks like this:
```
...
# # SMITH_INTERFACE # 
# # used to specify where the TPROXY will be applied. It should be usually i
# # the internal interface, heading to user machines which will be mitm'ed.
# # Action: you should adjust it according to your network setup.
# 
SMITH_INTERFACE='ens9'
...
```

### Certificate authority
You cannot magically break into or hack TLS. In order to do TLS MitM, you need certificate authority your applications trust which signs all faked certificates for you. There is default one pre-installed by smithproxy. You can use it, but   don't do that, please. There is a script `sx_regencerts` which can create one for you.

```
root@pixie:/# sx_regencerts 
Dry certificate check? [Dry/Normal]? Normal
Do you want to check and generate new certificates? [No/Yes]? Y
Checking installed certificates!
== Checking installed certificates ==
load_default_settings: exception caught: [Errno 2] No such file or directory: '/etc/smithproxy/certs/default/sslca.json'
== checking CA cert ==
default certificate!
    Default CA delivered by packaging system has been detected.
===> Do you want to generate your own CA? [yes/no]? yes
== checking default server cert ==
    certificate /etc/smithproxy/certs/default/srv-cert.pem valid.
    New default server certificate will be generated (new CA)
== checking portal cert ==
    certificate /etc/smithproxy/certs/default/portal-cert.pem valid.
    New portal certificate will be generated (new CA)
Which CA type you prefer? [rsa/ec]? ec
== generating a new CA == 
sign CSR: == extensions ==
sign CSR: <ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>
           CA=TRUE requested
           allowed by rule
sign CSR: == extensions ==
sign CSR: <ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>
... cannot load pylibconfig2 - cannot specify exact portal FQDN
sign CSR: == extensions ==
sign CSR: <ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>
...
root@pixie:/#
```

> `sx_regencerts` generates CA pair, server cert pair, client pair (not used) and portal cert. 
Portal certificate is most tricky one and `sx_regencerts` tries to play it smart.
* CA key-pair - used to fake original certificates
* Server cert key-pair - certificate is not used, only public and private key in it. key-pair is used to be construct CSR to generate faked certificate and then signed by CA.
* Portal cert - most tricky one. This is certificate for smithproxy login portal, if authentication is used. This portal FQDN is configurable in config file (see `settings/auth_portal/address setting`). It could be IP, but FQDN is nicer and preferred.

Ok, now `smithproxy` is finally using an unique CA certificate keypair. SSL applications passing smithproxy *MUST* trust this CA certificate, in order to work properly. You can display certificate issing this command:

```
root@pixie:/# cat /etc/smithproxy/certs/default/ca-cert.pem 
-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIKMXGTlQjGXjj+1TAKBggqhkjOPQQDAjBIMRswGQYDVQQD
DBJTbWl0aHByb3h5IFJvb3QgQ0ExHDAaBgNVBAoME1NtaXRocHJveHkgU29mdHdh
cmUxCzAJBgNVBAYTAkNaMB4XDTE5MTAxNzEwMjAyNFoXDTE5MTIxNzEwMjAyNFow
SDEbMBkGA1UEAwwSU21pdGhwcm94eSBSb290IENBMRwwGgYDVQQKDBNTbWl0aHBy
b3h5IFNvZnR3YXJlMQswCQYDVQQGEwJDWjBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABJt3NLpmEyNxSB0UflkYAGyBRDIWLdeLHqSRkBsIa9o/BhukhOFUqQOMhlks
fNZ9x+jpOP0oKpJshHdgHTw1++SjYzBhMB0GA1UdDgQWBBQhZ7zMNZYWfHHQtGl5
1OLmi8PxojAfBgNVHSMEGDAWgBQhZ7zMNZYWfHHQtGl51OLmi8PxojAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAy0p0
tAYbMnAS/oBdMuWlh5I+zDm3zJZzhosDRijC1oYCIECEqa9I+EY0Ak231MM8UEEr
MocNOo6Y4XArERJ8SEOD
-----END CERTIFICATE-----
```

** === IMPORTANT:** The certificate file **MUST** be imported to application trusted CA certificate list. 

You can also visually check it using openssl command:
```
root@pixie:/# openssl x509 -in /etc/smithproxy/certs/default/ca-cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            31:71:93:95:08:c6:5e:38:fe:d5
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Smithproxy Root CA, O = Smithproxy Software, C = CZ
        Validity
            Not Before: Oct 17 10:20:24 2019 GMT
            Not After : Dec 17 10:20:24 2019 GMT
        Subject: CN = Smithproxy Root CA, O = Smithproxy Software, C = CZ
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9b:77:34:ba:66:13:23:71:48:1d:14:7e:59:18:
                    00:6c:81:44:32:16:2d:d7:8b:1e:a4:91:90:1b:08:
                    6b:da:3f:06:1b:a4:84:e1:54:a9:03:8c:86:59:2c:
                    7c:d6:7d:c7:e8:e9:38:fd:28:2a:92:6c:84:77:60:
                    1d:3c:35:fb:e4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                21:67:BC:CC:35:96:16:7C:71:D0:B4:69:79:D4:E2:E6:8B:C3:F1:A2
            X509v3 Authority Key Identifier: 
                keyid:21:67:BC:CC:35:96:16:7C:71:D0:B4:69:79:D4:E2:E6:8B:C3:F1:A2

            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:cb:4a:74:b4:06:1b:32:70:12:fe:80:5d:32:
         e5:a5:87:92:3e:cc:39:b7:cc:96:73:86:8b:03:46:28:c2:d6:
         86:02:20:40:84:a9:af:48:f8:46:34:02:4d:b7:d4:c3:3c:50:
         41:2b:32:87:0d:3a:8e:98:e1:70:2b:11:12:7c:48:43:83

```
### Main configuration file */etc/smithproxy/smithproxy.cfg*
This file contains most of smithproxy settings to make it run. It's pre-set for safe values which won't hurt probably anyone. It's not configured for any capture, TLS security, bypass or any from other smithproxy fancy features.

##### Traffic policies
Probably first thing you gonna touch are policies. Let's have a look at one, allowing all traffic. They are processed top-down and contain many other settings and profiles. They look this way in their simplest form:
```
policy = (
    {
        proto = "udp";
        src = "any";
        sport = "all";
        dst = "any";
        dport = "dns";
        tls_profile = "default";
        detection_profile = "detect";
        content_profile = "default";
        auth_profile = "resolve";
        alg_dns_profile = "dns_default";
        action = "accept";
        nat = "auto";
    },
    {
        proto = "tcp";
        src = "any";
        sport = "all";
        dst = "any";
        dport = "all";
        tls_profile = "default";
        detection_profile = "detect";
        content_profile = "default";
        auth_profile = "resolve";
        alg_dns_profile = "dns_default";
        action = "accept";
        nat = "auto";
    }
)

###### Matching policy elements

```
First policy matches all *UDP* traffic. As you see, they contain different identifiers, referring to their own, respective config parts (6 is really TCP and 17 UDP):
```
proto_objects = {
    tcp = {
        id = 6;
    }
    udp = {
        id = 17;
    }
}
```
Also, there are IP address and port-range configuration objects.

First, let's see address objects:
```
address_objects = {
    any = {
        type = 0;
        cidr = "0.0.0.0/0";
    }
    root = {
        type = 1;
        fqdn = "www.root.cz";
    }
}
```
We have here two types, address (0) and fqdn (1). FQDN address is one learned from DNS. But don't worry, if it's not, smithproxy is trying to periodically refreshing them.
... and finally port objects:
```
port_objects = {
    all = {
        start = 0;
        end = 65535;
    }
    dns = {
        start = 53;
        end = 53;
    }
}
```
These are *matching* parts of policy. That being said, these are compared to traffic in order to decide if actions specified in the policy will be (or not) applied to the traffic. Obviously, if traffic matches, next policies are not attempted to match or process.

###### Action policy elements

```
policy = (
    {
        // ... action elements 
        action = "accept";
        nat = "auto";
    },
```
action = [ "accept" | "reject" ]
nat = [ "none" | "auto" ]

Setting `action = "accept"` or `reject` is obvious (accepting - passing traffic, or dropping it). 
Setting `nat = "none"` controls if traffic is attempted to keep its original IP and source port. This is supported for TPROXY traffic origin. Setting `nat = "auto"`, smithproxy will let it up to OS to decide what IP and port will be used (IP of outbound interface, and port from dynamic so-called ephemeral pool). 

###### Profile policy elements 

Let's start with example:
``` 
    },
    {
        // ....
        tls_profile = "default";
        detection_profile = "detect";
        content_profile = "default";
        auth_profile = "resolve";
        alg_dns_profile = "dns_default";
        // ....
    },
```
These are influencing what *will be done with the connection*:
 
* tls_profile - modify all related to TLS
* detection_profile - sets up flow-aware pattern matching engine on the connection
* content_profile - should be content changed, or ie. dumped into a file (.smcap)?
* auth_profile - should IP be authenticated (portal redirection)?
* alg_dns_profile - DNS settings, transparent DNS cache

##### Advanced configuration
We can't cover everything in quick howto document. However, you might be interested in following, most-frequently used features:

* Content dumping
* TLS parameters suitable for wireshark decryption


###### Content dumping to files

To write content into files, you need to:
1) set existing directory where to save .smcap files
```
settings = {
    // ...
    write_payload_dir = "/var/local/smithproxy/data";
    // ...
}
```
2) configure policy profile
```
content_profiles = {
    writer = {
        write_payload = TRUE;
        write_limit_client = 0;
        write_limit_server = 0;
    }
```
3) apply profile created above on the policy 
```
policy = (
    {
        proto = "tcp";
        src = "any";
        sport = "all";
        dst = "any";
        dport = "all";
        tls_profile = "default";
        detection_profile = "detect";
        content_profile = "writer";          // <--------------
        auth_profile = "resolve";
        alg_dns_profile = "dns_default";
        action = "accept";
        nat = "auto";
    }
)
```
4) restart smithproxy using `service smithproxy restart`

If followed correctly, you should now see in the directory .smcap files:
```
root@cr3:/var/local/smithproxy# find .
.
./data
./data/192.168.122.1
./data/192.168.122.1/2019-10-21
./data/192.168.122.1/2019-10-21/03-48-44_ssli_192.168.122.1:52098-ssli_172.217.23.202:443.smcap
./data/192.168.122.1/2019-10-21/04-28-27_ssli_192.168.122.1:57108-ssli_216.58.201.99:443.smcap
./data/192.168.122.1/2019-10-21/04-28-27_ssli_192.168.122.1:57092-ssli_172.217.23.196:443.smcap
./data/192.168.122.1/2019-10-21/04-30-57_ssli_192.168.122.1:57512-ssli_93.184.220.42:443.smcap
``` 

Smcaps are human-readable hexdump text files, later replayable by pplay tool.
```
Mon Oct 21 03:48:44 2019
+295518: ssli_192.168.122.1:52098-ssli_172.217.23.202:443(ssli_172.217.23.202:443-ssli_192.168.122.1:52098)
Connection start

Mon Oct 21 03:48:44 2019
+846830: ssli_192.168.122.1:52098-ssli_172.217.23.202:443(ssli_172.217.23.202:443-ssli_192.168.122.1:52098)
>[0000]   47 45 54 20 2F 76 34 2F   74 68 72 65 61 74 4C 69   GET./v4/ threatLi
>[0010]   73 74 55 70 64 61 74 65   73 3A 66 65 74 63 68 3F   stUpdate s:fetch?
>[0020]   24 63 74 3D 61 70 70 6C   69 63 61 74 69 6F 6E 2F   $ct=appl ication/

```
PPlay has its own howto on the project landing page here [pplay](https://bitbucket.org/astibal/pplay)

# Starting smithproxy

If everything above is set, you can start smithproxy using standard 
```
service smithproxy start
```
To make smithproxy start on boot, issue this command:
```
update-rc.s
```

# Smithproxy CLI
Smithproxy has its own CLI. Run `smithproxy_cli`, you will get output as follows:

```
root@cr3:~# smithproxy_cli 
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
--==[ Smithproxy command line utility ]==--

smithproxy(cr3) > 

```
run 
```
smithproxy(cr3) > enable
Password: 
smithproxy(cr3) #
```
to get privileged access. 

There are various command areas. Main are:

* `diag` - diagnostic output right to the CLI
* `debug` - set debug level for various aspects of smithproxy
    * `debug term` - sets output verbosity of CLI terminal
    * `debug file` - sets output verbosity for log file (`/var/log/smithproxy.log` by default)
* `configure` - this one is not yet implemented fully
* `save` - this one is not yet implemented fully

For example:
```
smithproxy(cr3) # diag proxy session list 
SocksProxy[MitmProxy: l:ssli_192.168.122.1:44252 <+> r:ssli_198.205.91.7:443  policy: 1 up/down: 0/5k]
SocksProxy[MitmProxy: l:ssli_192.168.122.1:44226 <+> r:ssli_198.181.99.133:443  policy: 1 up/down: 0/0]
SocksProxy[MitmProxy: l:ssli_192.168.122.1:44224 <+> r:ssli_51.215.192.131:443  policy: 1 up/down: 0/327k]
SocksProxy[MitmProxy: l:ssli_192.168.122.1:44228 <+> r:ssli_189.181.99.13:443  policy: 1 up/down: 5k/7k]
SocksProxy[MitmProxy: l:ssli_192.168.122.1:44204 <+> r:ssli_18.25.93.1:443  policy: 1 up/down: 5/114k]
SocksProxy[MitmProxy: l:ssli_192.168.122.1:45254 <+> r:ssli_192.241.15.28:443  policy: 1 up/down: 0/0]

Proxy performance: upload 5kbps, download 453kbps in last second

smithproxy(cr3) # diag ssl cache list 
certificate store entries: 
    /C=AU/L=Sydney/O=Atlassian Pty Ltd/CN=*.atlassian.com+san:DNS:*.atlassian.com+san:DNS:atlassian.com
    /C=AU/ST=New South Wales/L=Sydney/O=Atlassian Pty Ltd/CN=*.atlassian.com+san:DNS:*.atlassian.com+san:DNS:atlassian.com
    /C=US/ST=California/L=San Francisco/O=Atlassian, Inc./OU=Bitbucket/CN=*.bitbucket.org+san:DNS:*.bitbucket.org+san:DNS:bitbucket.org
    /C=US/ST=California/L=San Francisco/O=Atlassian, Inc./OU=Bitbucket/CN=bytebucket.org+san:DNS:bytebucket.org+san:DNS:www.bytebucket.org
/CN=root.cz+san:DNS:10.root.cz+san:DNS:beta.root.cz+san:DNS:blog.root.cz+san:DNS:cos.root.cz+san:DNS:root.cz+san:DNS:rss.root.cz+san:DNS:skoleni.root.cz+san:DNS:wiki.root.cz+san:DNS:www.root.cz+san:DNS:zdrojak.root.cz

smithproxy(cr3) # diag dns cache list 

DNS cache populated from traffic: 
    A:a.centrum.cz  -> [ttl:-158] ip4: 52.212.166.11 ip4: 52.16.169.136 ip4: 54.76.72.7
    A:a.1gr.cz  -> [ttl:1633] ip4: 54.76.72.7 ip4: 52.16.169.136 ip4: 52.212.166.11
    A:a.denik.cz  -> [ttl:-27] ip4: 52.16.169.136 ip4: 52.212.166.11 ip4: 54.76.72.7
    A:a.slunecnice.cz  -> [ttl:135] ip4: 54.76.72.7 ip4: 52.212.166.11 ip4: 52.16.169.136
    A:a.blesk.cz  -> [ttl:251] ip4: 52.16.169.136 ip4: 54.76.72.7 ip4: 52.212.166.11
    A:c1.navrcholu.cz  -> [ttl:226] ip4: 91.213.160.175
    A:fonts.gstatic.com  -> [ttl:8] ip4: 216.58.201.67
    A:s1.navrcholu.cz  -> [ttl:-41] ip4: 91.213.160.175
    A:www.root.cz  -> [ttl:-202] ip4: 91.213.160.188
    A:www.googletagservices.com  -> [ttl:-19102] ip4: 172.217.23.226
    A:eu.wargaming.net  -> [ttl:-40121] ip4: 92.223.19.57 ip4: 92.223.19.61

```