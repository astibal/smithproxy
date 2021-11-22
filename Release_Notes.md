# Smithproxy 0.9 Release Notes

[Smithproxy](https://www.smithproxy.org) is fast TLS/TCP/UDP/SOCKS mitm proxy written in C++. 

Smithproxy is being developed by:    
Ales Stibal `<astib@mag0.net>`


## Download and contacts

### Binary packages

* package: [https://download.smithproxy.org/](https://download.smithproxy.org/) (+changelogs)
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

## Roadmap for future versions

* [ ] memory pool ONLY execution
* [ ] routing - SNI-based, ... more options

## What's new in 0.9.26

* [x] routing - DNAT fixed, load-balanced

* add 'routing' load-balance criteria: source-IP, L3 (srcIP+dstIP), L4 (srcIP+dstIP+dstPORT)
* add 'routing' to more targets - aka load-balance
* CHANGE: --tenant-index is now no-op (smithproxy reads index from tenants config)

* major fix - resolve memory corruption under heavy load caused by socle mempool data race condition
* fix - write PID if run in foreground (to help with systemd integration)
* fix minor multi-tenancy support problems and improvements 
* logging optimizations - less memory copying in several places 

## What's new in 0.9.25

hotfix release

* fixed problem in smithproxy start when upgrading config file

## What's new in 0.9.24
* added 'routing' configuration element, currently, DNAT can be configured (more to come)
* improve a bit SNI bypass, which now supports '*.example.com' notation
* internal improvement of shm semaphore vs. udp mutex locks
* few more fixes

## What's new in 0.9.23
* **CHANGE:** pcap quota now in megabytes (values will be converted automatically on upgrade)
* **CHANGE:** new dependency: libmicrohttpd
* added a limited json/api interface
 
  * JSON API: proxy connections detail
  * JSON API: certificate cache list/stats
  * JSON API: smithproxy status

* fix crash on transparent source IP detection
* fix crash in sx_regencerts tool

##  What's new in 0.9.21
This is a hotfix release:

* fix pcap file rollover race condition

## What's new in 0.9.20

### New features in 0.9.20
* add support for PCAP file capture (multiple, or single capture file) with rollover capability
* pass TLS ALPN extension - controllable by 'alpn_block' in TLS profile
* signature cascades
* new version config file migration support

### Improvements in 0.9.20
* introduction of engines - similar to inspectors, but working more closely with data     
* add cli command 'diag proxy session active' which prints only currently active sessions
* match starttls only on certain traffic and exchange margins
* new 'toggle' command - modify list variables - toggle specific element instead of setting all at once
* code cleanups in logging - removal of old macros

### Fixes
* fix memory leak in socle logging subsystem  

## What's new in 0.9.13
 
### New features
* new `diag ssl ticket clear` to clear tls session data
* [x] memory profiles - more flexible mempool controlled by percentile env. variable SX_MEMSIZE 
* [x] better certificate cache - certificates from cache expire on LRU-similar basis
* [x] **new installations affecting change** split portal services and core   

### Improvements
* introduce SX_MEMSIZE env variable to control how many buffers are allocated
* libcidr changes - refactored into namespace
* tls session cache is now set to lru mode  
* libcli changes - code base switched to new 'main' branch with few changes
* certificate cache changes - cache is now based on custom lru scheme 
* portal split - there are now 2 packages: smithproxy and smithproxy-auth 

### Fixes
* 2 smaller memory leaks fixed
* fix dns inspector - allow NS type in authority responses and allow records into cache 


## What's new in 0.9.12

### New features
* portal spit - portals moved to smithproxy_auth project (core package detects portals on restart)

* **0.9.12**
* **0.9.12 RC2**  
  see fixes
* **0.9.12 RC1**
* smithproxy has now extensive CLI configuration support 
* release builds don't require libunwind (which is good news on some platforms)
* experimental memory mode  'mempool_all' - leak troubleshooting feature (must be compiled in)
* cli `set` commands will expand full chain of argument values if attribute is array
* cli policy `move` command improved by `up|down|top|bottom` directives (ie. command `move [3] top`)
* docs improved with inline docker scenario overview
* cli help and hint mechanics improvements 
* cli: allow attribute empty values, better value change checks
* add new cli command `move` into policy section with `before [x]` and `after [y]` directives
* add new cli command `add` into policy section (creates a new disabled policy)
* add new attributes in the `policy`: `disabled` and `name`  
    * `disabled` - will make policy inactive - policy won't match any traffic
    * `name` - convenience attribute for describing the policy
* significantly improved CLI edit/add/remove commands - partial rewrite - getting to know libcli
* added `remove` support for policy section
* CLI `remove` dependency checks -> safe remove
* added CLI command `remove` ~~- use with caution, removes also used items, which leads to policy load failure~~
* added CLI command `add` which ... adds new configuration elements into *running config* (not all elements are covered
 yet) 
* added Certificate Transparency support (tls_profile/ct_enable option) - enabled by default  
    1) use new shell command `sx_download_ctlog` to download CT logs and make CT checks available
    2) restart service to activate CT checks
    3) config must be saved and reloaded to make it visible in CLI and config file (`save config`, `exec reload`)
* new build system, .deb package releases should appear more frequently on the server (amd64+armhf (v8): Ubuntu 20.04, 18.04 and Debian 10).
* added Release Notes 
* added sha256 sums to build uploads

### Bug fixes & various

* **0.9.12 RC2**
* fix CLI 'set' commands appearing where they shouldn't
* fix TLS profiles - some options were not working 
* fix clunky override replacement mechanics
* **0.9.12 RC1**
* fix (stability) occasional CPU spikes during TLS handshake caused by sockets input race
* fix daemon factory handling of pid files (fixes 'randomly not stopping via server or sx_ctl')
* fix various mempool_all crashes on exit (mempool is experimental - common releases are not affected) 
* fix abort call from signal handler - use _exit
* fixed resource leak by not releasing socket from map 
* fixed memory leak in sobjectdb
* new file download server
* fixed arm64 ubuntu20.04 build
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
* docker ubuntu, mode TPROXY -- routed traffic, also from/to docker0 
* docker ubuntu, mode REDIRECT   -- heavy testing on main development system
* docker ubuntu, mode SOCKS5 with DNS 
* kvm ubuntu guest, mode TPROXY  
* kvm ubuntu guest, mode REDIRECT
* kvm guest alpine, build and startup only (aka should work)

### ARMv8 (RockPro64 - CPU RK3399)
* ubuntu, mode SOCKS5+DNS
