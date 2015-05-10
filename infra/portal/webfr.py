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
import ssl
import CGIHTTPServer
import pylibconfig2 as cfg
import sys
import os
import time
import logging


def run_plaintext(cfg_api, server_class=BaseHTTPServer.HTTPServer,
        handler_class=CGIHTTPServer.CGIHTTPRequestHandler):
  
    port = cfg_api.settings.auth_portal.http_port
    server_address = ('', int(port))
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)
    CGIHTTPServer.CGIHTTPRequestHandler.have_fork=False    
    httpd.serve_forever()


def run_ssl(cfg_api,server_class=BaseHTTPServer.HTTPServer,
        handler_class=CGIHTTPServer.CGIHTTPRequestHandler):
  
    port = cfg_api.settings.auth_portal.https_port
    
    cert_root = cfg_api.settings.certs_path
    key  = cert_root+cfg_api.settings.auth_portal.ssl_key
    cert = cert_root+cfg_api.settings.auth_portal.ssl_cert
  
    server_address = ('', int(port))
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


def run_portal_plain():
    ret = True
    try:
        logging.debug("run_portal_plain: start")
        c = cfg.Config()
        c.read_file("/etc/smithproxy/smithproxy.cfg")  
        run_plaintext(c)
    except Exception, e: 
        ret = False;
        logging.error("run_portal_plain: exception caught: %s" % (str(e)))
        
    return str(ret)
       
def run_portal_ssl():
    ret = True
    try:
        logging.debug("run_portal_ssl: start")
        c = cfg.Config()
        c.read_file("/etc/smithproxy/smithproxy.cfg")  
        run_ssl(c)
    except Exception, e: 
        ret = False;
        logging.error("run_portal_ssl: exception caught: %s" % (str(e)))
        
    return str(ret)





