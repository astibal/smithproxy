
[**Smithproxy**](https://www.smithproxy.org) is highly configurable, fast and transparent TCP/UDP/TLS (SSL) proxy
 written in C++17.  
It uses our C++17 socket proxying library called [*socle*](https://github.com/astibal/socle). 

> **Note:** Snap and precompiled binary packages are no longer available from Russia Federation and Belarus as a response
> to their blatant war crimes being committed when invading Ukraine these days.
> For individuals from named countries: there are still sources which can be easily compiled; in the mean time seek more uncensored information!

> Read fresh [**Release Notes**](https://download.smithproxy.org/0.9/Release_Notes.md) to stay tuned!  
> Documentation: [https://smithproxy.readthedocs.org](https://smithproxy.readthedocs.org)  
> To replay captured traffic, check out the sister project [pplay](https://pypi.org/project/pplay/).


## Availability:
* **Linux** - can be installed as a service (distro packages, or easily compiled from sources)
    * Download  binary linux .deb (*arm64*, *armhf*, *amd64*) packages and source from: [https://download.smithproxy.
      org/](https://download.smithproxy.org/)
    * Download and compile directly from source (known to work: Debian, Ubuntu, Alpine, Fedora, Kali, Arch)
* **Docker** - available as an image on docker hub
    * See our docker hub page: [https://hub.docker.com/r/astibal/smithproxy](https://hub.docker.com/r/astibal/smithproxy)
    * ![](https://img.shields.io/docker/pulls/astibal/smithproxy)
* **Snap** - install smithproxy service as a confined snap (with some limitations)!
    * Visit snap store here: [https://snapcraft.io/smithproxy](https://snapcraft.io/smithproxy)

## Core features:
* TCP/UDP and TLS - intercept **routed** traffic, **locally-originated** traffic and **SOCKS** proxy requests
* configure policy based traffic matching similar to modern firewalls
* utilize per-policy applicable *content*, *dns*, *tls*, *detection* and *authentication* profiles
* re-route traffic (DNAT) and load-balance it, stickiness based on source-IP, L3 or L4 header data
* enjoy insightful CLI with configuration control
* export intercepted traffic to rotated pcap files, or emitting it to remote workstation in GRE

## TLS features:
* TLS security checks (OCSP, OCSP stapling, automatic CRL download)
* custom certificates based on target IP or SNI
* Certificate Transparency checks for outbound connections
* HTML replacement browser warnings
* STARTTLS support for most starttls capable protocols, including HTTP proxy CONNECT
* Seamless HTTPS redirection to authentication portal
* Exporting sslkeylog
* KTLS support (level of acceleration depends on OpenSSL version)

## Other:
* Local and LDAP user authentication using builtin web portal (using complementary package)
* SOCKS4/SOCKS5 and HTTP CONNECT explicit proxies with DNS hostname support
* Engines: limited HTTP1 and HTTP2 support
* DNS inspection allows FQDN policy objects, including DoH
* Policies based on FQDN and 2nd level DNS domain
* both IPv4 and IPv6 are supported
* detailed debugging messages in CLI if needed
* various sinkhole options - traffic is captured but not proxied

## Tools:
* built-in tools to help with CA and certificate enrollment needed to run smithproxy
* auto-enrolling portal certificate based on system IP and hostname
* auto-detect inspection interface(s) based on system routing information
* check [pplay tool](https://pypi.org/project/pplay/): replays captures
  over the network with many cool features

## HTTP CONNECT explicit proxy

The HTTP/1.0 and HTTP/1.1 `CONNECT host:port` listener uses the same policy,
DNS resolution and TLS/STARTTLS interception path as the SOCKS listener. IPv4,
IPv6 (`CONNECT [::1]:443`) and FQDN authorities are accepted.

Enable it in `etc/smithproxy.cfg`:

```text
settings = {
    accept_http_connect = TRUE;
    http_connect_port = "3128";
    http_connect_workers = 0; // automatic worker count; -1 disables workers
};
```

The listener returns `200` after the upstream connection succeeds, `400` for
invalid requests, `403` when policy rejects the connection, `431` when the
header reaches the 8 KiB limit, and `502` for resolution or upstream connection
failure. Requests and error responses close the connection where appropriate.

Current limitation: application data sent in the same TCP segment immediately
after the CONNECT headers can be discarded during the frontend-to-tunnel
handoff. Clients should wait for `200 Connection Established` before sending
tunnel data. CONNECT request pipelining is not supported.

### Support and contacts
  * Discord server: [https://discord.gg/vf4Qwwt](https://discord.gg/vf4Qwwt)  
  * email support: `<support@smithproxy.org>`  
  * Documentation: [https://smithproxy.readthedocs.org](https://smithproxy.readthedocs.org)  
