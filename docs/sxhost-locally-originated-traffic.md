# Inspecting smithproxy locally originated traffic

This is a mini-howto describing how to set up smithproxy inspection for locally originated traffic.  

## Scenario

```
+-- SX host -----+  
|                |  
|   [smithproxy] |  
|                |  
|   [your app]---------------> OUT    
|                |  
+----------------+  
```

## TCP traffic

This is possible with some limitations by utilizing OUTPUT iptables chain. Only limitation is  we cannot in default 
installation divert `root` user traffic.  
Because smithproxy is originating traffic on behalf of depicted `your app`, it would hit again OUTPUT chain and create
a loop.  That's the reason why we need to distinguish traffic not intended for further redirection. user-id is the 
simplest way to do it.  
> **If you *need* to inspect root user traffic, this scenario is not possible to follow.**   
>  Only solution is to run smithproxy as different user with root privileges, but it's not implemented yet.     

Smithproxy listens by default on `51080` (plain) and `51443` (tls) ports for incoming redirected traffic. Please don't 
use tproxy ports, it will not work.  

How to divert local tcp traffic to smithproxy:  
  
``` 
iptables -t nat -A OUTPUT -p tcp -d 0.0.0.0/0 --dport 80 -j REDIRECT --to-port 51080 -m owner ! --uid-owner root 
iptables -t nat -A OUTPUT -p tcp -d 0.0.0.0/0 --dport 443 -j REDIRECT --to-port 51443 -m owner ! --uid-owner root
```


## UDP traffic

UDP output chain redirection is problematic for smithproxy and similar applications. Original destination IP address is 
possible to extract only on fully connected UDP socket. Smithproxy (and others) can't use fully connected UDP sockets.  
Because of such a technical limitation
> Smithproxy supports UDP only for DNS, sending traffic to preconfigured DNS servers. Also, only non-root user 
> traffic shall be diverted to smithproxy.
    

Example of diverting locally originated DNS: 
```     
iptables -t nat -A OUTPUT -p udp -d 8.8.4.4 --dport 53 -j REDIRECT --to-port 51053 -m owner ! --uid-owner root                        
iptables -t nat -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-port 51053 -m owner ! --uid-owner root   
```

Such a traffic is then sent to congfigured DNS, see `smithproxy.cfg`:
```
settings = {
   nameservers = ("8.8.8.8", "8.8.4.4");
   // ... 
```


## Conclusion

With some limitations, locally originated TCP and DNS traffic can be **transparently** inspected, without configuring 
the end application. 

Both conditions must be met:

* traffic must not be owned by root
* UDP is considered as DNS traffic and is sent to preconfigured nameservers in `smithproxy.cfg` 


