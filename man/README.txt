This document should describe how to run smithproxy and how to test it's features.

INSTALLATION

1. apply content of tpoxy.txt in the router. You can add there as many ports as you want, just bear in mind that redirection to 50080 
   will run in plaintext only, UNLESS it detects STARTTLS procedure. Traffic redirected to 50043 will start SSL immediatelly.
2. check your certificates, they should be in certs/ directory under smithproxy $CWD. Smithproxy will complain what's missing.
3. run ./smithproxy # possibly with --diagnose or --debug flags 

BASIC CONNECTIVITY TESTS

1. run webserver
2. run wget stuff
HTTP:
wget -c http://192.168.132.1/100k -O /dev/null
wget http://speedtest.diino.com/largefiles/file-10M.bin -O /dev/null
HTTPS:
wget --no-check-certificate -c https://192.168.132.1/100k -O /dev/null
wget --no-check-certificate https://speedtest.diino.com/largefiles/file-10M.bin -O /dev/null

You should see similar output (taken from version Smithproxy 0.3.5)
14-09-17 13:21:25.1410952885 <140591749068544> Informal - Connection from 192.168.100.40:45042 to 192.168.132.1:443 established
14-09-17 13:21:27.1410952887 <140591749068544>  Warning - Connection from 192.168.100.40:45042 to 192.168.132.1:443 matching signature: cat='www', name='http/get|post' at <0,15>,<0,12>
14-09-17 13:23:23.1410953003 <140591749068544> Informal - Connection from 192.168.100.40:45042 to 192.168.132.1:443 closed, sent=1/115B received=51/102618B

STARTTLS SUPPORT TEST
Below you can find some starttls sites. Always check logs if */starttls should appear AND issuer in s_client output.

openssl s_client -host smtp.gmail.com -port 25 -starttls smtp
openssl s_client -host imap.seznam.cz -port 143 -starttls imap
openssl s_client -host mail2.fortinet.com -port 110 -starttls pop3
openssl s_client -host secureftp-test.com -port 21 -starttls ftp
openssl s_client -connect isj3cmx.webexconnect.com:5222 -starttls xmpp
# lsap with starttls is not yet supported

14-09-17 13:56:21.1410954981 <140465965889280> Informal - Connection from 192.168.100.40:52542 to 64.65.53.241:21 established
14-09-17 13:56:22.1410954982 <140465965889280>  Warning - Connection from 192.168.100.40:52542 to 64.65.53.241:21 matching signature: cat='files', name='ftp/starttls' at <0,-1>,<0,9>,<0,7>
14-09-17 13:56:30.1410954990 <140465965889280> Informal - Connection from 192.168.100.40:52542 to 64.65.53.241:21 closed, sent=1/10B received=2/76B


APP,AV SIGNATURES
1. create file 'eicar' with X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* somewhere in the content in your webserver /
2. try download:
wget -c http://192.168.132.1/eicar -O /dev/null
wget --no-check-certificate -c https://192.168.132.1/eicar -O /dev/null

14-09-17 14:03:25.1410955405 <139851069159168>  Warning - Connection from 192.168.100.40:36066 to 192.168.132.1:80 matching signature: cat='www', name='http/get|post' at <0,9>,<0,12>
14-09-17 14:03:25.1410955405 <139851069159168>  Warning - Connection from 192.168.100.40:36066 to 192.168.132.1:80 matching signature: cat='av', name='virus/eicar' at <0,-1>,<245,566>
14-09-17 14:03:25.1410955405 <139851069159168> Informal - Connection from 192.168.100.40:36066 to 192.168.132.1:80 closed, sent=1/116B received=1/322B

14-09-17 14:07:37.1410955657 <139851077551872> Informal - Connection from 192.168.100.40:40884 to 192.168.132.1:443 established
14-09-17 14:07:37.1410955657 <139851077551872>  Warning - Connection from 192.168.100.40:40884 to 192.168.132.1:443 matching signature: cat='www', name='http/get|post' at <0,9>,<0,12>
14-09-17 14:07:37.1410955657 <139851077551872>  Warning - Connection from 192.168.100.40:40884 to 192.168.132.1:443 matching signature: cat='av', name='virus/eicar' at <0,-1>,<245,566>
14-09-17 14:07:38.1410955658 <139851077551872> Informal - Connection from 192.168.100.40:40884 to 192.168.132.1:443 closed, sent=1/116B received=2/322B

You should see both, signature matching protocol and also eicar. Note that EICAR should be detected also in HTTPS, we are SSL mitm proxy!

