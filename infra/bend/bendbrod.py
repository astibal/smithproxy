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

import logging
import socket

import SOAPpy
from M2Crypto import SSL
import pylibconfig2 as cfg

class BendBroker:

    def __init__(self,tenant_index=0,tenant_name=None):
        
        self.tenant_index = int(tenant_index) 
        self.tenant_name = "default"
        if tenant_name:
            self.tenant_name = tenant_name
        
        self.cert_file = '/etc/smithproxy/certs/default/srv-cert.pem'
        self.key_file = '/etc/smithproxy/certs/default/srv-key.pem'

        self.context = SSL.Context()
        self.context.load_cert(self.cert_file,keyfile=self.key_file)

        self.service_port = 65000 + self.tenant_index
        self.bend_port = 64000 + self.tenant_index

        self.l_server = SOAPpy.ThreadingSOAPServer(("0.0.0.0", self.service_port),ssl_context = self.context)
        self.r_server = SOAPpy.SOAPProxy("http://localhost:%d/" % (self.bend_port,))

        self.l_server.registerFunction( SOAPpy.MethodSig(self.ping, keywords=0, context=1) )
        self.l_server.registerFunction( SOAPpy.MethodSig(self.whoami, keywords=0, context=1) )
        self.l_server.registerFunction( SOAPpy.MethodSig(self.authenticate, keywords=0, context=1) )

        self.create_logger()
        self.load_config()

    def create_logger(self):
        self.log = logging.getLogger('bendbro')
        hdlr = logging.FileHandler("/var/log/smithproxy_bendbro.%s.log" % (self.tenant_name,))
        formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
        hdlr.setFormatter(formatter)
        self.log.addHandler(hdlr) 
        self.log.setLevel(logging.INFO)        

    def load_config(self):
        self.cfg = cfg.Config()
        self.cfg.read_file("/etc/smithproxy/smithproxy.cfg")    


    """ return addresses where real cotact can be done """
    def ping(self,_SOAPContext = None):
        portal_address = self.cfg.settings.auth_portal.address
        portal_port = self.service_port
        fqdn = socket.getfqdn()
        
        s = "https://%s:%s/" % (portal_address,portal_port)
        sq = "https://%s:%s/" % (fqdn,portal_port)
        
        r = [s,sq]
        
        return r
        


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
        self.log.warning("Backend broker daemon started (tenant name %s, index %d)" % (self.tenant_name,self.tenant_index) )
        self.log.info("listening on port: %d" % (self.service_port,) )
        self.log.info("backend port set to: %d" % (self.bend_port,) )
        self.l_server.serve_forever()


if __name__ == "__main__":
    b = BendBroker(0,"default")
    b.run()
