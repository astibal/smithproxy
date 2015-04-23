# INTRODUCTION
Wportals is a collection of server pages served by smithproxy 
in order to:
    - validate user (login screen)
    - display replacement messages in case it's needed (blocked content)
    
## Directories:
bend/
    bend.py 
        - python backend server
        - SOAPpy server to handle requests from various wportals compoents
        - it really authenticates the user 
    shmtable.py
    shmbuffer.py
        - abstraction for data written in shared memory
        - shmtable.shm_table can handle table table versions and is good start 
          as base class
          
    
bendc/    ... shm backend client for C++ (it won't speak SOAP)
    shmtestsuite.cpp 
        - templated function to call if concurent data load/save/display is needed.
        - well documented
    shmtest.cpp
        - shmtest <logon|token> : adds random logons|tokens into shm table
        - scans for new versions
        - good to start study how it works
        
smithauth/
    cgi-bin/
        auth.py - logon page generator
        auth2.py - logon accepter - redirector
        util.py - generator for errors/warnings
        
    index.html
        - plain redirector to cgi-bin/auth.py ... (to be removed?)
    webfr.py
        - super-easy python server ... serving current directory.
        - motivation is to avoid package dependencies - no apache/nginx, etc.
        - should be someday something more robust, but now it's good/fast enough.
        
        
        
# APPENDIX
notes:
some parts taken from nlotp project

auth-portal should be protected with per-IP syn rate limiter:
iptables -A INPUT -p tcp --syn --dport <smithauth_port> -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset  

soappy bend could be also used for JSON <-> pythonlibconfig2 structures
