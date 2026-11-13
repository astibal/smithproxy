====

Welcome in smithproxy .dpkg building platform

All you need is to run a script, respective to your branch of interest.

====

QUIC defaults to the pinned ngtcp2 source submodule, linked statically with its
OpenSSL crypto adapter. Populate submodules before packaging source archives.
The default build requires CMake >= 3.20 and system OpenSSL >= 3.5; it does not
require distribution ngtcp2 development or runtime packages.

To deliberately build the compatibility backend:
  SMITHPROXY_ENABLE_NGTCP2=OFF ./createdeb-0.9.sh <branch>
or, for a direct Debian build:
  DEB_BUILD_PROFILES=pkg.smithproxy.openssl-quic dpkg-buildpackage -us -uc

The profile permits older OpenSSL development packages and passes OFF to CMake.
dh_shlibdeps supplies the actual ABI-specific runtime dependencies, so do not
hard-code libngtcp2, libssl, libcurl or other shared-library package names.
