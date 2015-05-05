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


import sys, time
from daemon import Daemon
import subprocess
import distutils
import logging
import os
import pprint

class SmithProxyDog(Daemon):
        def __init__(self,poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'): 
            Daemon.__init__(self,'/var/run/smithdog.pid',stdin,stdout,stderr)
            self.exec_info = []     # tuples of nicename,executable,pidfile_of_executable
            self.sub_daemons = {}   # daemons which have been started
            self.poll_interval = poll_interval
            
        def run(self):
            while True:
                for (nicename,exe,pidfile) in self.exec_info:
                    running = False
                    try:
                        pid = Daemon.readpid(pidfile)
                        if pid:
                            os.kill(pid,0)
                            running = True
                        
                    except OSError, e:
                        pass
                    
                    logging.info("Status of '" + nicename + "': " + str(running))
                        
                time.sleep(self.poll_interval)

    
if __name__ == "__main__":
        logging.basicConfig(filename='/var/log/smithproxy_dog.log', level=logging.INFO, format='%(asctime)s %(message)s')
    
        daemon = SmithProxyDog(5)
        daemon.exec_info.append(('smithproxy backend','/usr/local/bin/smithproxy_bend','/var/run/smithproxy_bend.pid'))
        daemon.exec_info.append(('smithproxy portal','/usr/local/bin/smithproxy_portal','/var/run/smithproxy_portal.pid'))
        daemon.exec_info.append(('smithproxy daemon','/usr/local/bin/smithproxy','/var/run/smithproxy.pid'))
        
        if len(sys.argv) == 2:
                if 'start' == sys.argv[1]:
                        daemon.start()
                        #daemon.run()
                elif 'stop' == sys.argv[1]:
                        daemon.stop()
                elif 'restart' == sys.argv[1]:
                        daemon.restart()
                else:
                        print "Unknown command"
                        sys.exit(2)
                sys.exit(0)
        else:
                print "usage: %s start|stop|restart" % sys.argv[0]
                sys.exit(2)
