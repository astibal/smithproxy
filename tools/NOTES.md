### NOT WORKING - Amazon linux 2 (Karoo)

This fails to compile due to old GCC. In theory, you can download newer GCC toolchain
and try to use it.

> fails to compile because old GCC 7.3.1


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