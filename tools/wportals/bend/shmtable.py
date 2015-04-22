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

    def load(self):
        print "---load:"
        self.seek(0)
        v,n,r = self.read_header()
        
        if r != self.row_size:
            print "Incompatible rowsize! Expecting %d, got %d" % (self.row_size,r)
            return False
        
        if not self.is_updated(v):
            print "---same version: %d, entries: %d, rowsize: %s" % (v,n,r)
        else:
            print "---updated version: %d, entries: %d" % (v,n)
        
            self.on_new_version(self.version,v)

            
            for i in range(0,n):
                s = self.read(self.row_size)
                self.on_new_entry(s)

            self.ack_updated(v)
            self.on_new_finished()
            
            if self.normalize:
                self.save(True)    
                # despite this is not really necessary, we will do so, in order to act following common-sense.
                print "NORMALIZED"


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
