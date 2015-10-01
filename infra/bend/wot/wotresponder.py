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

import SocketServer

from daemon import create_logger
from wotcon import Wot,WotResult

flog = create_logger("wotc","/var/log/smithproxy_wotc.log")
READ_SIZE = 1024

class WotResponder(SocketServer.BaseRequestHandler):

    def handle(self):
        data = ""
        
        while True:
            data_temp = self.request.recv(READ_SIZE)
            data += data_temp
            if len(data_temp) < READ_SIZE:
                break
        
        w = Wot("57a92fd16754f60359c4d7fb6dd8b5ea7a26039e")        
        w_r = WotResult(w.rate(str(data)))
        d = w_r.process()       
       
        flog.info("incoming wot request for " + str(data))
        flog.info("incoming wot response " + str(d))
       
        self.request.sendall("ok")
        
        
        
        
        