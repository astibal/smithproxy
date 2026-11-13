# Package build images

Ubuntu 26.04 and its debug image are the default-capable ngtcp2 package builders.
All Dockerfiles default to `SMITHPROXY_ENABLE_NGTCP2=ON`; missing OpenSSL 3.5+ fails
instead of changing the transport. Older images need suitable distro backports
or the deliberate `--build-arg SMITHPROXY_ENABLE_NGTCP2=OFF` compatibility build.

`sx-builder.py` forwards `--ngtcp2 ON` (default) or `--ngtcp2 OFF` to Docker.
The choice reaches both linux-deps.sh and Debian's build profile/rules.
No private OpenSSL sources, patches or build paths are part of these images.

Recursive source checkout includes the pinned ngtcp2 submodule. The transport
and crypto adapter are linked statically; no distro ngtcp2 package is required.
