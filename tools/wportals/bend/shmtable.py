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

import time
import mmap
import os
import sys
import struct
import posix_ipc

PY_MAJOR_VERSION = sys.version_info[0]

import SOAPpy

class ShmTable:

    def __init__(self):
	  self.header_size = 0
	  self.memory_size = 0
	  self.memory_name = ""
	  self.semaphore_name = ""
	  
	  self.memory = None
	  self.semaphore = None
	  self.mapfile = None
	  self.my_version = None

    def setup(self,mem_name, mem_size, sem_name):

	  self.memory_size = mem_size
	  self.memory_name = mem_name
	  self.semaphore_name = sem_name
	  
	  self.memory = posix_ipc.SharedMemory(self.memory_name, posix_ipc.O_CREX, size=self.memory_size)
	  self.semaphore = posix_ipc.Semaphore(self.semaphore_name, posix_ipc.O_CREX)

	  self.mapfile = mmap.mmap(self.memory.fd, self.memory.size)

	  # Once I've mmapped the file descriptor, I can close it without interfering with the mmap. 
	  self.memory.close_fd()
	  
	  self.semaphore.release()

	  ### now init
	  
    def clear(self):	  
	  self.seek(0)
	  self.write("\x00"*self.memory_size)

    def release(self):
	  self.semaphore.release()
	  
    def acquire(self):
	  self.semaphore.acquire()

    def write(self, s):
	self.semaphore.release()
	self.semaphore.acquire()

	if PY_MAJOR_VERSION > 2:
	    s = s.encode()
	    
	self.mapfile.write(s)

    def read(self,num):
	return self.mapfile.read(num)


    def seek(self,pos):
	self.mapfile.seek(pos)

    def cleanup(self):
	self.semaphore.release()
	time.sleep(5)
	self.semaphore.acquire()

	self.mapfile.close()
	posix_ipc.unlink_shared_memory(self.memory_name)

	self.semaphore.release()
	self.semaphore.unlink()
      
