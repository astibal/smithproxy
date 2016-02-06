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


import traceback
import time
import mmap
import os
import sys
import struct
import socket
import logging

from shmtable import ShmTable


flog = logging.getLogger('bend')

class LogonTable(ShmTable):             

    def __init__(self):
        ShmTable.__init__(self,4+64+128)
        self.logons = {}
        self.normalizing = True

    def add(self,ip,user,groups):

        self.logons[ip] = [ip,user,groups]
        self.save(True)
        
    def rem(self,ip):
        if ip in self.logons.keys():
            self.logons.pop(ip, None)
            self.save(True)
            
    def save(self, inc_version=False):
        self.seek(0)
        self.clear()
        self.write_header(inc_version,len(self.logons.keys()))
        
        for k in self.logons.keys():
              try:
                  self.write(struct.pack("4s64s128s",socket.inet_aton(k),self.logons[k][1],self.logons[k][2]))
              except IndexError:
                  flog.warning("LogonTable: IndexError: not in logons: " + k + " " + str(e))
                  continue

        self.normalize = False # each dump effectively normalizes db

    def on_new_version(self,o,n):
        self.logons = {}
        
    def on_new_entry(self,blob):
        
        i,u,g = struct.unpack("4s64s128s",blob)
        ip = socket.inet_ntoa(i)
        
        tag = ''
        if ip in self.logons.keys():
            tag = ' (dup)'

        if self.normalizing:
            self.normalize = True

        self.logons[ip] = [ip,u.strip('\x00').strip(),g.strip('\x00').strip()]
        flog.debug("on_new_entry: added " + ip + tag + ", " + u.strip() + ", " + g.strip())
        

        return True

    def on_new_finished(self):
        pass
