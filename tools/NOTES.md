### NOT WORKING - Amazon linux 2 (Karoo)

This fails to compile due to old GCC. In theory, you can download newer GCC toolchain
and try to use it.

```bash
export SX_SPYNE_VER="==2.13.2a0"

yum update -y
yum install -y git
yum install -y libconfig libconfig-devel openssl11 openssl11-devel gcc gcc-c++

# libcli not present as a package
git clone --recursive https://github.com/dparrish/libcli
cd libcli/ && make install && cp libcli.h /usr/include/ && cd ..

yum install -y python3-devel
yum install -y libunwind libunwind-devel 
yum install -y cmake3 python3-devel
yum install -y kernel-headers glibc-headers

yum install -y telnet iptables iproute
yum install -y openldap-devel libffi-devel libxml2-devel swig

yum install -y python3-pip
pip install --upgrade pip
pip install wheel
pip install python-ldap pyparsing posix-ipc
pip install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography

# old cmake 2.x doesn't recognize python3 dev paths
ln -sf /usr/bin/cmake3 /usr/bin/cmake

git clone --recursive https://github.com/astibal/smithproxy

# fails to compile because old GCC 7.3.1
```


#### Kali Linux - docker issues

This could be a problem on my host only.

```bash
root@c6d999ca7b06:/smithproxy# /etc/init.d/smithproxy start               
cfg portal address is IP
sign CSR: == extensions ==
sign CSR: <ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>
portal certificate regenerated
starting smithproxy
Smithproxy iptables chains setup script - start tenant: 0

Preparing chain SX.0 capturing traffic on eth0


<waiting forever...>
```
this is probably due to some iptables docker<->container interoperability issue. 