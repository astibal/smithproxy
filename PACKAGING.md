# Smithproxy build and packaging

The build has one payload definition and two packaging paths:

```text
                         install.cmake
                              |
                cmake --install (staging tree)
                       /              \
              CPack TGZ/DEB       debian/ + debhelper
              developer build     production DEB
```

`tools/linux-*.sh` remain supported entry points for distro setup and smoke
tests. The commands below are the lower-level, deterministic interface.

All build and packaging commands in this document start in the repository
root: the directory containing `CMakeLists.txt`, `debian/` and `tools/`.

```text
/path/to/smithproxy/          repository root; run commands here
├── build/                    generated CMake build trees
├── debian/                   native Debian packaging metadata
└── tools/                    build and package helpers

/path/to/                     native Debian package output (one level above)
```

## 1. Local build

Configure and build one of the named presets:

```sh
cd /path/to/smithproxy       # repository root
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug
```

For an optimized build, replace `debug` with `release`.

The preset name also determines the build directory:

```text
build/debug
build/release
build/package
```

The existing convenience build remains available:

```sh
cd /path/to/smithproxy       # repository root
sudo tools/linux-deps.sh
sudo tools/linux-build.sh
```

## 2. Verify the install manifest without touching the host

Never use `sudo` for a staging install:

```sh
cd /path/to/smithproxy       # repository root
cmake --preset package
cmake --build --preset package --parallel
DESTDIR="$PWD/build/stage" cmake --install build/package
find build/stage -type f -o -type l
```

`DESTDIR` prepends a temporary root. An install intended for `/usr/bin` lands
in `build/stage/usr/bin`, not in the running system.

## 3. Quick developer packages with CPack

```sh
cd /path/to/smithproxy       # repository root
cmake --preset package
cmake --build --preset package --parallel
cpack --config build/package/CPackConfig.cmake -G TGZ
```

On Debian or Ubuntu, a quick binary package can also be generated with:

```sh
# still in /path/to/smithproxy
cpack --config build/package/CPackConfig.cmake -G DEB
```

CPack packages are convenient artifacts. They deliberately contain no Debian
upgrade policy or service lifecycle scripts. Use the native package below for
installation on managed systems.

## 4. Production Debian/Ubuntu package

Install build dependencies reported by Debian:

```sh
cd /path/to/smithproxy       # repository root
sudo apt-get build-dep .
tools/package-deb.sh
```

Both commands run from the repository root. The resulting native packages are
written one level above it. For example:

```sh
cd ..                        # now in /path/to
ls smithproxy_*.deb smithproxy_*.changes
cd smithproxy                # return to the repository root
```

Debian outputs packages and metadata in the parent directory. Debug symbols
are generated automatically as a separate `smithproxy-dbgsym` package.

The package:

- derives shared-library dependencies from the built executable;
- installs configuration below `/etc/smithproxy` as dpkg conffiles;
- creates the `_sxy` system account and runtime directories idempotently;
- leaves service activation to an explicit administrator action;
- never downloads Python packages from the network in a maintainer script.

The packaged systemd service runs as root because transparent interception
changes routing and firewall state. Capability-only operation is an explicit
administrator configuration; the package does not modify the executable's
file capabilities behind the administrator's back.

Activate the default tenant when its configuration is ready:

```sh
# working directory does not matter for systemctl
sudo systemctl enable --now sx-network@default.service
sudo systemctl enable --now sx-core@default.service
```

Run package QA before publishing:

```sh
cd /path/to/smithproxy       # repository root
lintian ../smithproxy_*.changes
sudo autopkgtest ../smithproxy_*.changes -- null
```

The complete install/upgrade/remove/purge lifecycle can be tested in a clean
container for any supported Debian-family target:

```sh
cd /path/to/smithproxy       # repository root
tools/test-deb-package.sh --list
tools/test-deb-package.sh debian-13
```

The package must be rebuilt on every target distribution. Shared-library
dependencies are derived from that target's binary, so a package built on a
new Ubuntu release is not assumed to run on an older Debian release.

For clean, reproducible release builds use `sbuild` with a dedicated chroot;
`tools/package-deb.sh` is intentionally also usable inside that builder.

## 5. Versioning and releases

The program version is declared by `project(... VERSION ...)` in
`CMakeLists.txt`. Debian adds its own revision in `debian/changelog`:

```text
upstream version       0.9.32
Debian version         0.9.32-1
snapshot example       0.9.32+git20261009.6688819-1
```

Prepare a release entry with `dch`, review it, then build:

```sh
cd /path/to/smithproxy       # repository root
dch --newversion 0.9.33-1 --distribution unstable "New upstream release."
tools/package-deb.sh
```

Source packages additionally require an upstream tarball matching the version
in `debian/changelog`. Binary development builds do not.

## Ownership boundaries

```text
CMakeLists.txt / install.cmake   files and their installation destinations
debian/                          Debian dependencies, upgrades and services
CMakePresets.json                repeatable developer configurations
tools/package-deb.sh             small command-line wrapper only
tools/linux-*.sh                 cross-distribution convenience and CI
```

Do not add upload credentials or repository publication to the package build.
Building and publishing are separate operations so a failed upload can never
change what was built.
