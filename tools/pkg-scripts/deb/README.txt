====

Welcome in smithproxy .dpkg building platform

All you need is to run a script, respective to your branch of interest.

====

QUIC defaults to ngtcp2, including its OpenSSL crypto adapter. Use repositories
providing ngtcp2 >= 1.16 and OpenSSL >= 3.5 (for example Ubuntu 26.04).
The default Debian build dependencies enforce these requirements.

To deliberately build the compatibility backend:
  SMITHPROXY_ENABLE_NGTCP2=OFF ./createdeb-0.9.sh <branch>
or, for a direct Debian build:
  DEB_BUILD_PROFILES=pkg.smithproxy.openssl-quic dpkg-buildpackage -us -uc

The profile removes ngtcp2 build dependencies and passes OFF to CMake.
dh_shlibdeps supplies the actual ABI-specific runtime dependencies, so do not
hard-code libngtcp2, libssl, libcurl or other shared-library package names.
