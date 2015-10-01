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


import sys
import os
import socket
import threading
import daemon

import SocketServer

class Responder_OK(SocketServer.BaseRequestHandler):

    ok_response = "OK"

    def handle(self):
        data = self.request.recv(1024)
        cur_thread = threading.current_thread()
        response = self.ok_response
        
        self.request.sendall(response)

class ThreadedUxServer(SocketServer.ThreadingMixIn, SocketServer.UnixStreamServer):
    pass

class ThreadedUxServerDaemon(daemon.Daemon):
    def __init__(self, nicename, pidfile,socketname,responder):
        daemon.Daemon.__init__(self,nicename,pidfile)
        self.socketname = socketname
        self.responder = responder
    
    def run(self):
        try:
            os.unlink(self.socketname)
        except OSError:
            pass
        
        self.server = ThreadedUxServer(self.socketname,self.responder,bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.server_bind()
        self.server.server_activate()
        self.server.serve_forever()

if __name__ == "__main__":
    
    def test_client(message):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect("/tmp/test-ux-server.sck")
        try:
            sock.sendall(message)
            response = sock.recv(1024)
            print "Received: {}".format(response)
        finally:
            sock.close()

    if len(sys.argv) > 1:
        if sys.argv[1] == "server" or sys.argv[1] == "s":
            d = ThreadedUxServerDaemon("test-ux-server","/tmp/test-ux-server.pid","/tmp/test-ux-server.sck",Responder_OK)
            d.restart()
            #if not d.start():
                #print "Try to stop..."
                #d.stop()
                #print "done."
                #d.start()
                
            sys.exit(0)
        
    test_client("test string 1")                                                                                                                                                 
    test_client("test string 2")                                                                                                                                                 
    test_client("test string 3")                                                                                                                                                 
                                                                                                                                                                            
