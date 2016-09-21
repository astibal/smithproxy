#!/usr/bin/env python
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



import BaseHTTPServer, SimpleHTTPServer
from SocketServer import ThreadingMixIn

import socket
import ssl
import CGIHTTPServer
import pylibconfig2 as cfg
import sys
import os
import time
import logging

global TENANT_NAME
global TENANT_IDX
global flog

class ThreadingCGIServer(ThreadingMixIn,BaseHTTPServer.HTTPServer):
    address_family = socket.AF_INET6

def create_portal_logger(name):
    ret = logging.getLogger(name)
    hdlr = logging.FileHandler("/var/log/smithproxy_%s.log" % (name,))
    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    ret.addHandler(hdlr) 
    ret.setLevel(logging.INFO)
    
    return ret


def run_plaintext(cfg_api, server_class=ThreadingCGIServer,
        handler_class=CGIHTTPServer.CGIHTTPRequestHandler):
  
    port = int(cfg_api.settings.auth_portal.http_port)  + int(TENANT_IDX)
    server_address = ('::', int(port))
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)
    CGIHTTPServer.CGIHTTPRequestHandler.have_fork=False    
    httpd.serve_forever()


def run_ssl(cfg_api,server_class=ThreadingCGIServer,
        handler_class=CGIHTTPServer.CGIHTTPRequestHandler):
  
    port = int(cfg_api.settings.auth_portal.https_port) + int(TENANT_IDX)
    
    cert_root = cfg_api.settings.certs_path
    key  = cert_root+cfg_api.settings.auth_portal.ssl_key
    cert = cert_root+cfg_api.settings.auth_portal.ssl_cert
  
    server_address = ('::', int(port))
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket (httpd.socket, keyfile=key,certfile=cert, server_side=True)
    CGIHTTPServer.CGIHTTPRequestHandler.have_fork=False
    httpd.serve_forever()


def run_portal_all_background():

    c = cfg.Config()
    c.read_file("/etc/smithproxy/smithproxy.cfg")  
  
    for ps_name,callable in [("http",run_plaintext),
                            ("https",run_ssl)]:
        r,w = os.pipe()
        pid = os.fork()

        if pid == 0:
            continue
        else:
            logging.debug("Starting %s process..." % (ps_name,))
            callable(c)
            time.sleep(1)


def run_portal_plain(tenant_name,tenant_idx,drop_privs_routine=None):
    global TENANT_NAME,TENANT_IDX,flog
    TENANT_NAME = tenant_name
    TENANT_IDX  = tenant_idx
    flog = create_portal_logger("portal_plain.%s" % (tenant_name,))
    
    os.environ['TENANT_NAME'] = tenant_name
    os.environ['TENANT_IDX'] = tenant_idx
    
    ret = True
    try:
        flog.info("Plaintext portal: start")
        c = cfg.Config()
        c.read_file("/etc/smithproxy/smithproxy.cfg")  
        
        if drop_privs_routine:
            flog.info("dropping privilegges")
            drop_privs_routine()        
            flog.info("done")
            
        run_plaintext(c)
    except Exception, e: 
        ret = False;
        flog.error("run_portal_plain: exception caught: %s" % (str(e)))
        
    return str(ret)
       
def run_portal_ssl(tenant_name,tenant_idx,drop_privs_routine=None):
    global TENANT_NAME,TENANT_IDX,flog
    TENANT_NAME = tenant_name
    TENANT_IDX  = tenant_idx
    flog = create_portal_logger('portal_ssl.%s' % (tenant_name,))

    os.environ['TENANT_NAME'] = tenant_name
    os.environ['TENANT_IDX'] = tenant_idx
    
    ret = True
    try:
        flog.info("SSL portal: start")
        c = cfg.Config()
        c.read_file("/etc/smithproxy/smithproxy.cfg")  
        
        if drop_privs_routine:
            flog.info("dropping privilegges")
            drop_privs_routine()
            flog.info("done")            
        
        run_ssl(c)
    except Exception, e: 
        ret = False;
        flog.error("run_portal_ssl: exception caught: %s" % (str(e)))
        
    return str(ret)





