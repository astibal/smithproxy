# Smithproxy 0.9 Release Notes

[Smithproxy](https://www.smithproxy.org) is fast TLS/TCP/UDP/SOCKS mitm proxy written in C++. 

Smithproxy is being developed by:    
Ales Stibal `<astib@mag0.net>`


## Download and contacts

### Binary packages

* package: [https://www.mag0.net/out/smithproxy](https://www.mag0.net/out/smithproxy) (+changelogs)
* snap:    [https://snapcraft.io/smithproxy](https://snapcraft.io/smithproxy)
* docker:  [https://hub.docker.com/r/astibal/smithproxy](https://hub.docker.com/r/astibal/smithproxy)

### Source

* git: [https://github.com/astibal/smithproxy](https://github.com/astibal/smithproxy)

To build smithproxy from source, please download source tarball and read instructions in `tools/README.md`.  
It should compile on any recent Linux system with C++17 compiler (GCC is used and tested).

### Getting support

* Discord server: [https://discord.gg/vf4Qwwt](https://discord.gg/vf4Qwwt)
* email support: `<support@smithproxy.org>`
* Documentation: [https://smithproxy.readthedocs.org](https://smithproxy.readthedocs.org)

## What's new in 0.9.12 (in progress)

### New features

* added Certificate Transparency support (tls_profile/ct_enable option) - enabled by default  
    1) use new shell command `sx_download_ctlog` to download CT logs and make CT checks available
    2) restart service to activate CT checks
    3) config must be saved and reloaded to make it visible in CLI and config file (`save config`, `exec reload`)
* new build system, .deb package releases should appear more frequently on the server (amd64+armhf (v8): Ubuntu 20.04, 18.04 and Debian 10).
* added Release Notes 
* added sha256 sums to build uploads

### Bug fixes
* fixed crash on exit in case proxy startup fails  


## What's new in 0.9.11

### New features

There are following changes in `0.9.11` compared to `0.9.7` release:

* UDP code totally rewritten - no "quick" mode ports anymore. "quick_ports" configuration option is now no-op and will be remove
in the future releases.
* new proxy multiplexer with different and more robust internal connection handover and routing
* memory pool system totally rewritten to almost lock-free mechanism
* new `diag worker list` CLI command to diagnose new worker architecture
* new `diag mem udp stats` CLI command to diagnose new UDP flow datagrams (they will become a connection)
* new config `settings/` area bool variables: `accept_tproxy`, `accept_redirect` and `accept_socks` to fully disable respective worker trees and save some idle CPU cycles + startup script support for these.
* reworked automatized build system - new binary package builds don't require any intervention and are compiled and uploaded to mag0.net/out/smithproxy repository automatically.

### Bug fixes

* `0.9.11-2` Fix new installations startup problems caused to zero size shared memory SIGBUS exit



# Tested platforms

While there are still no guarantees, smithproxy is regularly tested with user internet traffic on platforms and systems as below.
Note the list is not exhaustive and my differ based on release type and new features added. 

### AMD64/x86
* docker ubuntu, mode REDIRECT   -- heavy testing on main development system
* docker ubuntu, mode SOCKS5 with DNS 
* kvm ubuntu guest, mode TPROXY  
* kvm ubuntu guest, mode REDIRECT
* kvm guest alpine, build and startup only (aka should work)

### ARMv8 (RockPro64 - CPU RK3399)
* ubuntu, mode SOCKS5+DNS
