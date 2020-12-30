
[**Smithproxy**](https://www.smithproxy.org) is highly configurable, fast and transparent TCP/UDP/TLS (SSL) proxy
 written in C++17.  
It uses our C++17 socket proxying library called [*socle*](https://github.com/astibal/socle). 

> Read fresh [**Release Notes**](https://www.mag0.net/out/smithproxy/0.9/Release_Notes.md) to stay tuned!  
> Documentation: [https://smithproxy.readthedocs.org](https://smithproxy.readthedocs.org)  
> To replay captured traffic, check out the sister project [pplay](https://pypi.org/project/pplay/).


### Availability:
  * **Linux** - can be installed as a service (distro packages, or easily compiled from sources)  
    * Download Linux .deb (*armv8*, *amd64*) packages from: [https://smithproxy.org/out/0.9/](https://smithproxy.org/out/0.9/)  
    * Download and compile directly from source (known to work: Debian, Ubuntu, Alpine, Fedora, Kali)  
  * **Docker** - available as an image on docker hub  
    * See our docker hub page: [https://hub.docker.com/r/astibal/smithproxy](https://hub.docker.com/r/astibal/smithproxy)  
  * **Snap** - you can also install it as a confined snap!  
    Visit snap store here: [https://snapcraft.io/smithproxy](https://snapcraft.io/smithproxy)  

### Core features:
  * intercept **routed** traffic, **locally-originated** traffic and **SOCKS** proxy requests
  * configure policy based traffic matching similar to modern firewalls
  * utilize per-policy applicable *content*, *dns*, *tls*, *detection* and *authentication* profiles
  * enjoy insightful CLI with configuration control

### TLS features:
  * dumping plaintext version of traffic to files, exporting sslkeylog
  * TLS security checks (OCSP, OCSP stapling, automatic CRL download)
  * Certificate Transparency checks for outbound connections
  * HTML replacement browser warnings
  * STARTTLS support for most used protocols
  * Seamless HTTPS redirection to authentication portal

### Other:
  * Local and LDAP user authentication using builtin web portal
  * SOCKS4/SOCKS5 explicit proxy with DNS hostname support
  * DNS inspection allows FQDN policy objects
  * Policies based on FQDN and 2nd level DNS domain
  * both IPv4 and IPv6 are supported

### Tools:
  * built-in tools to help with CA and certificate enrollment needed to run smithproxy
  * auto-enrolling portal certificate based on system IP and hostname
  * auto-detect inspection interface(s) based on system routing information
  * check [pplay tool](https://pypi.org/project/pplay/): replays captures
    over the network with many cool features  

### Support and contacts
  * Discord server: [https://discord.gg/vf4Qwwt](https://discord.gg/vf4Qwwt)  
  * email support: `<support@smithproxy.org>`  
  * Documentation: [https://smithproxy.readthedocs.org](https://smithproxy.readthedocs.org)  
