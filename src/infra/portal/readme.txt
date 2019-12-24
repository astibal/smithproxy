
notes:
lot of stuff removed; if needed, take a look in the nlotp dir in archives


auth-portal should be protected with per-IP syn rate limiter:
iptables -A INPUT -p tcp --syn --dport <smithauth_port> -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset  


soappy bend could be also used for JSON <-> pythonlibconfig2 structures





Some of my notes/snippets for furher coding:
============================================

# pip install pylibconfig2
# pip install pyparsing

import pylibconfig2 as cfg
c = cfg.Config()
c.read_file("/etc/smithproxy/smithproxy.cfg")

# usage:
# c.settings.auth_portal.ssl_key
# 