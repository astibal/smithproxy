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
    
import time
import mmap
import os
import sys
import struct
import posix_ipc
import socket

from shmbuffer import ShmBuffer

class ShmTable(ShmBuffer):
    def __init__(self,row_size):
        ShmBuffer.__init__(self)
        self.version = 0
        self.header_size = 12
        #self.row_size = 4+64+128
        self.row_size = row_size
        self.normalizing = False                # should we fix database in key conflict?
        self.normalize = False                  # temp status
        self.entries = []
        
    def write_header(self, inc_version=False,n_entries=None):
        self.seek(0)
        
        if inc_version:
            self.version = self.version + 1
            
        write_entries = len(self.entries)
        if n_entries:
            write_entries = n_entries

        self.write(struct.pack('III',self.version,write_entries,self.row_size))
        

    def read_header(self):
        self.seek(0)
        s = self.read(self.header_size)
        version,no_entries,rowsize = struct.unpack('III',s)

        return version,no_entries,rowsize
      
    def is_updated(self, v):
        if v != self.version:
           return True
         
    def ack_updated(self, a):
        self.version = a

    def load(self, forced=False):
        # print "---load:"
        self.seek(0)
        v,n,r = self.read_header()
        
        if r != self.row_size:
            print "Incompatible rowsize! Expecting %d, got %d" % (self.row_size,r)
            return False
        
        if not self.is_updated(v) and not forced:
            #print "---same version: %d, entries: %d, rowsize: %s" % (v,n,r)
            pass
        else:
            #print "---updated version: %d, entries: %d" % (v,n)
            pass
        
            self.on_new_version(self.version,v)

            
            for i in range(0,n):
                s = self.read(self.row_size)
                self.on_new_entry(s)

            self.ack_updated(v)
            self.on_new_finished()
            
            if self.normalize:
                self.save(True)    
                # despite this is not really necessary, we will do so, in order to act following common-sense.
                # print "NORMALIZED"


    def save(self, inc_version=False):
        self.seek(0)
        self.clear()
        self.write_header(inc_version)
        for e in self.entries:
            self.write(e)

        self.normalize = False # each dump effectively normalizes db

    def on_new_version(self,o,n):
         self.entries = []
         
    def on_new_entry(self,s):
         self.entries.append(s)
         
    def on_new_finished(self):
         pass
