# Smithproxy README#

Smithproxy is free transparent proxy software. It utilizes TPROXY and is capable to proxy TCP and UDP connnections.
It does have its own web page: [www.smithproxy.org](http://www.smithproxy.org)

##Features:##
* SSL Mitm with certificate resigning -- trusted CA in browser will prevent certificate warnings
* STARTTLS support for of starttls capable protocols, including SMTP,FTP,IMAP and POP3.

##Binary builds:##
You can obtain smithproxy in DEB packages here:
http://www.mag0.net/out/smithproxy/

##Building from sources:##
If you want to build smithproxy from sources, feel free. Current setup is done the way that you have to have socle and smithproxy
directories in the same folder.  
I am using simple script which makes it easy (I am just editing it):

```
#!shell

# cat fetch.sh
SMITHPROXY_USER="astibal"
SMITHPROXY_BRANCH="0.4"
SOCLE_USER="astibal"
SOCLE_BRANCH="0.1"

git clone git@bitbucket.org:${SMITHPROXY_USER}/smithproxy.git -b ${SMITHPROXY_BRANCH}
git clone git@bitbucket.org:${SOCLE_USER}/socle.git -b ${SOCLE_BRANCH}
```
1. adjust the above and run it
2. go to smithproxy/build  (you can create build directory if necessary)
3. run 'cmake .. && make'
4. if you have all dependencies installed, you will see smithproxy executable in the build/.



### What is this repository for? ###

* This is official GIT repository for smithproxy project
* Current version is 0.4.0beta1. 

### How do I get set up? ###

* Summary of set up

* Configuration
Configuration is located in /etc/smithproxy/smithproxy.cfg file
You will need also certificates for ssl resigning  (ssl mitm)

**TBA:**

* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact