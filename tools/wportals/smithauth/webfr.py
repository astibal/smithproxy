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



import BaseHTTPServer
import CGIHTTPServer

def run(server_class=BaseHTTPServer.HTTPServer,
        handler_class=CGIHTTPServer.CGIHTTPRequestHandler):
    server_address = ('', 8008)
    handler_class.cgi_directories = ['/cgi-bin']
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

run()
