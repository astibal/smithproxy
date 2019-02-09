
**>>>** For general information go here: [www.smithproxy.org](http://www.smithproxy.org) **<<<**  


You can reach us also here:  
[Discord server](https://discord.gg/vf4Qwwt)

Mailing lists:  
[smithproxy-users](mailto:smithproxy-users@googlegroups.com)  
[smithproxy-announce](mailto:smithproxy-announce@googlegroups.com)



## Something for docker users 
**currently easiest way to test smithproxy is docker!**

To run smithproxy, issue something like this:

```
# -- create settings volume
sudo docker volume create sxy

# -- create logging volume
sudo docker volume create sxyvar

# -- create packet dump volume
sudo docker volume create sxydumps


# -- run actual smithproxy container
sudo docker run -v sxy:/etc/smithproxy -v sxyvar:/var/log -v sxydumps:/var/local/smithproxy -it \
                        --rm --network host astibal/smithproxy:latest
```


##### Before you start with testing


You will see certificate on smithproxy startup. Copy this certificate,
and add it in your browser trusted root CA list.
This certificate will be used to sign spoofed target server certificates.
Unless set,  your browser experience will be really painful.

---
**Important**: 
This is serious. Cryptographically you are allowing smithproxy 
to actually terminate TLS on itself, and opening a new TLS connection to your 
originally intended server.   
As the user, you are now only controlling security of the connection between you 
and smithproxy. The rest is not in your hand (it's in hands of smithproxy). 
---

 
Then, you can then point your browser to port 1080, and test. You should not 
see much issues. Browsing is ok, and smithproxy is in its default config,
which is intended for demonstration purposes (no OCSP, hacking features disabled).

##### After you are done with testing

I strongly recommend to remove previously added CA certificate from trusted 
root certificate authorities! Of course it applies to all places you did this, 
not only your browser.


#### Where to look further

All your files should be accessible from docker host, if you used volumes, as suggested above. I am 
mentioning here full paths how they look inside of container. 

###### sxy volume
`/etc/smithproxy/` - all config rules 
  * `smithproxy.cfg` - policies and profiles. There is a ton and half of things to play with.  
  * `users.cfg` - user databases and realms (disabled by default)
 

###### sxyvar volume
`/var/log/smithproxy*` - various logging files. 
  * `smithproxy.cfg` - general logging of smithproxy daemon

###### sxydumps volume
`/var/local/smithproxy/data` - content writer target directory (disabled by default)
  

#### smithproxy CLI

`smithproxy_cli` is your friend. Once you got CLI, type `enable` to elevate your privileges.
CLI looks like this:
```
    root@pixie:/app# smithproxy_cli 
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    --==[ Smithproxy command line utility ]==--
    
    smithproxy(pixie) > en
    Password: 
    smithproxy(pixie) # 
    
    smithproxy(pixie) # diag proxy session list
    MitmProxy: l:tcp_192.168.122.1:54942 <+> r:tcp_109.233.72.84:80  policy: 1 up/down: 0/35.35M
    MitmProxy: l:ssli_192.168.122.1:47030 <+> r:ssli_181.160.161.165:443  policy: 1 up/down: 0/0
    MitmProxy: l:ssli_192.168.122.1:47040 <+> r:ssli_172.240.130.251:443  policy: 1 up/down: 0/12k
```
... yes, it's telnet to localhost. If you don't like it, submit patches. And yes, you can see 
actual connection speed in the rightmost column.

#### Restarting smithproxy

You might need it one day. 
```
/etc/init.d/smithproxy restart
```
You will see many privilege-related errors. You can ignore them in this testing image. 
Image is intended to be used in non-privileged mode, therefore only SOCKS4 or SOCKS5 could be used.
Transparent proxying might not work properly, as you need to route traffic directly to container.


