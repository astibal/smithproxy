#!/usr/bin/env python3
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
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
    """





import ssl

from http.server import CGIHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ThreadingMixIn

import pylibconfig2 as cfg

import os
import time
import logging

global TENANT_NAME
global TENANT_IDX
global flog


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        pass


def create_portal_logger(name):
    ret = logging.getLogger(name)
    hdlr = logging.FileHandler("/var/log/smithproxy_%s.log" % (name,))
    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    ret.addHandler(hdlr) 
    ret.setLevel(logging.INFO)
    
    return ret


def run_plaintext(cfg_api, server_class=ThreadingHTTPServer, handler_class=CGIHTTPRequestHandler):
  
    port = int(cfg_api.settings.auth_portal.http_port) + int(TENANT_IDX)
    server_address = ('', int(port))
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


def run_ssl(cfg_api,server_class=ThreadingHTTPServer,
        handler_class=CGIHTTPRequestHandler):
  
    port = int(cfg_api.settings.auth_portal.https_port) + int(TENANT_IDX)
    
    cert_root = cfg_api.settings.certs_path
    key = cert_root+cfg_api.settings.auth_portal.ssl_key
    cert = cert_root+cfg_api.settings.auth_portal.ssl_cert
  
    server_address = ('', int(port))
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)

    # this is very tricky one! Solving plaintext in TLS traffic
    # -- https://stackoverflow.com/questions/27303343/python3-cgi-https-server-fails-on-unix
    handler_class.have_fork=False

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(sock=httpd.socket, server_side=True)
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


def run_portal_plain(tenant_name,tenant_idx, drop_privs_routine=None):
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
            flog.info("dropping privileges")
            drop_privs_routine()        
            flog.info("done")
            
        run_plaintext(c)
    except Exception as e:
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
            flog.info("dropping privileges")
            drop_privs_routine()
            flog.info("done")            
        
        run_ssl(c)
    except Exception as e:
        ret = False;
        flog.error("run_portal_ssl: exception caught: %s" % (str(e)))
        
    return str(ret)





