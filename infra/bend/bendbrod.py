"""
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.  """


import SOAPpy
from M2Crypto import SSL
import pylibconfig2 as cfg

BEND_LOGFILE="/var/log/smithproxy_bend.log"


class BendBroker:

    def __init__(self):
       self.cert_file = '/etc/smithproxy/certs/default/srv-cert.pem'
       self.key_file = '/etc/smithproxy/certs/default/srv-key.pem'

       self.context = SSL.Context()
       self.context.load_cert(self.cert_file,keyfile=self.key_file)

       self.l_server = SOAPpy.ThreadingSOAPServer(("0.0.0.0", 65457),ssl_context = self.context)
       self.r_server = SOAPpy.SOAPProxy("http://localhost:65456/")

       self.l_server.registerFunction( SOAPpy.MethodSig(self.whoami, keywords=0, context=1) )
       self.l_server.registerFunction( SOAPpy.MethodSig(self.authenticate, keywords=0, context=1) )


    def whoami(self,_SOAPContext = None):
       if _SOAPContext:
           ip = _SOAPContext.connection.getpeername()[0]
           return self.r_server.whois(ip)

       return []


    def authenticate(self, username, password, _SOAPContext = None):
       if _SOAPContext:
           ip = _SOAPContext.connection.getpeername()[0]
           return self.r_server.authenticate(ip,username,password,"0")

       return False,"http://auth-portal-url/"

    def run(self):
       self.l_server.serve_forever()




b = BendBroker()
b.run()
