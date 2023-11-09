## Quick Installation Guide

### 1. Download and build (.deb based distros)

Install essential build tools
```shell
apt update && apt -y install git cmake 
```

Cone repo including submodules (this will get latest `master` version)
```shell
git clone https://github.com/astibal/smithproxy.git --depth 1 --recurse-submodules
```

Run utility build scripts
```shell
cd smithproxy && ./tools/linux-deps.sh && ./tools/linux-build.sh
```

### 2. Basic setup

```shell
# download SCT logs (Certificate Transparency)
sx_download_ctlog

# interactive CA generator script (say Y to first question)
sx_regencerts

# enable services, restart them 
systemctl enable sx-network@default
systemctl enable sx-core@default

systemctl restart sx-network@default
systemctl restart sx-core@default
```

### 3. Use CLI to configure further (CLI has a Cisco+FortiGate vibe)

```shell
sx_cli
```
You will get:
```
root@sx-host:/smithproxy# sx_cli 
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
--==[ Smithproxy command line utility ]==--

smithproxy(sx-host)>
```
Gain enable (privileged access), see config and diag possibilities
```
smithproxy(sx-host)> enable
smithproxy(sx-host)# config term
smithproxy(sx-host) (config)# edit ?
  settings               - edit settings
  debug                  - edit debug
  proto_objects          - edit proto_objects
  address_objects        - edit address_objects
  port_objects           - edit port_objects
  detection_profiles     - edit detection_profiles
  content_profiles       - edit content_profiles
  tls_profiles           - edit tls_profiles
  auth_profiles          - edit auth_profiles
  alg_dns_profiles       - edit alg_dns_profiles
  routing                - edit routing
  captures               - edit captures
  policy                 - edit policy
  starttls_signatures    - edit starttls_signatures
  detection_signatures   - edit detection_signatures

```
>> CLI is quite powerful, you can do vast majority changes there.  
Only very limited set of changes require `sx-core@default` restart.


```
smithproxy(sx-host)# diag proxy 
  policy              proxy policy commands
  session             proxy session commands
  io                  proxy I/O related commands
```

## MITM specific configuration 
Please don't forget to read also final **Notes** section!

### Disable TLS checks (act like mitm proxy, not like a firewall)
We don't want to be intrusive. Allow connecting to everything, and don't replace content if there is a problem.   
Also, log `SSLKEYLOG` to `/var/log/smithproxy/sslkeylog.default.log` (optional).
```
configure terminal 
    edit tls_profiles 
        edit default 
            set allow_untrusted_issuers true
            set allow_invalid_certs true
            set allow_self_signed true 
            set ct_enable false
            set failed_certcheck_replacement false
            set sslkeylog true
        end
    end
exit
save config
```

### Configure traffic capture

Enable and customize *global* capturing options. 
Most convenient is to use GRE and send traffic from `sx-host` to your workstation (ie. running wireshark).
There is also an option to save files locally, but once you try remote GRE, you will not use it :) 
```
configure terminal
    edit captures
        edit remote
            set tun_dst <replace with your workstation IP>
            set tun_ttl 16
            set enabled true
        end
    end
exit
            
```

Content profile `default` is used in pre-installed policies.
> >**Important note**: only policies using this content_profile will capture traffic.

```
configure terminal
    edit content_profiles
        edit default
            set write_payload true
        end
    end
exit
save config
```

## Notes

- File locations  
    `/etc/smithproxy/` - all configurations   
    `/var/smithproxy/` - local capture files (bit nonstandard directory, sorry)   
    `/var/log/smithproxy/` - log files, including `SSLKEYLOG`
    

- Not all traffic routed via `sx-host` is diverted to `smithproxy`.   
    By default, only traffic from interfaces not having _default route associated_ are diverted.  
    This can be changed in `smithproxy.startup.cfg`. (requires `sx-network@default` restart).      
```
# SMITH_INTERFACE='-'    # '-' : enable on downlink interfaces (without default route applied)
                         # '*' : enable on ALL interfaces
```
