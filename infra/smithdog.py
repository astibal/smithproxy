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

from portal import webfr

class PortalDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)
        
    def run(self):
        e = None
        logging.info("PortalDaemon.run: starting "+self.nicename)
        if(self.nicename.endswith("ssl")):
            logging.info("PortalDaemon.run: starting ssl ("+self.nicename+")")
            e = webfr.run_portal_ssl()
        else:
            logging.info("PortalDaemon.run: starting plain ("+self.nicename+")")
            e = webfr.run_portal_plain()
        
        if(e):
            logging.error("portal finished with error: %s",str(e))
        else:
            logging.info("portal finished...")
            
        time.sleep(1)
        sys.exit(1)
        
    

class SmithProxyDog(Daemon):
    def __init__(self,poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'): 
        Daemon.__init__(self,'smithdog','/var/run/smithproxy_dog.pid',stdin,stdout,stderr)
        self.exec_info = []     # tuples of nicename,executable,pidfile_of_executable
        self.sub_daemons = []   # daemons which we are starting via Daemon class interface
        self.poll_interval = poll_interval
    
    def status(self,print_stdout=False,auto_restart=True):
        
        ret = True
        r = SmithProxyDog.check_running_pidfile(self.pidfile)
        if not r: 
            SmithProxyDog.print_process_status(r,self.nicename,print_stdout)
            ret = r
            if auto_restart:
                msg = "Cannot automatically fix myself: please run the 'start' parameter"
                logging.error(msg)
                if print_stdout:
                    print msg
                
        
    
        for (nicename,exe,pidfile) in self.exec_info:
            r = SmithProxyDog.check_running_pidfile(pidfile)
            if not r: 
                SmithProxyDog.print_process_status(r,nicename,print_stdout)
                ret = r
                if auto_restart:                
                    msg = "fixing: " + exe
                    logging.info(msg)
                    if print_stdout:
                        print msg
                    # some real fixing action
         

        for d in self.sub_daemons:
            r = SmithProxyDog.check_running_pidfile(d.pidfile)
            if not r: 
                SmithProxyDog.print_process_status(r,d.nicename,print_stdout)        
                ret = r
                if auto_restart:                
                    msg = "fixing sub-daemon: " + d.nicename
                    logging.info(msg)
                    if print_stdout:
                        print msg

                    p = os.fork()
                    if p == 0:                        
                        d.start()
                
        
        if ret:   
            msg = "Status of all monitored processes is OK"
            logging.info(msg)
            if print_stdout:
                print msg
                
        return ret
    
    def run(self):
        while True:
            self.status(False)
            time.sleep(self.poll_interval)

    @staticmethod
    def print_process_status(r,nicename,print_stdout=False):
            statmsg = "NOT running"
            if r:
                statmsg = "running"
            if not print_stdout:
                logging.info("Status of '" + nicename + "': " + statmsg)  
            else:
                print "Status of '" + nicename + "': " + statmsg

    @staticmethod
    def check_running_pidfile(pidfile):
        
        running = False
        try:
            pid = Daemon.readpid(pidfile)
            if pid:
                os.kill(pid,0)
                running = True
            
        except OSError, e:
            pass
        
        return running

    
if __name__ == "__main__":
    logging.basicConfig(filename='/var/log/smithproxy_dog.log', level=logging.INFO, format='%(asctime)s [%(process)d] %(message)s')

    daemon = SmithProxyDog(5)
    daemon.keeppid = True

    daemon.exec_info.append(('smithproxy daemon','/usr/local/bin/smithproxy','/var/run/smithproxy.pid'))
    
    ### Portal INIT 
    
    portal = PortalDaemon('portal','/var/run/smithproxy_portal.pid')
    #portal.should_chdir = False
    daemon.sub_daemons.append(portal)
    
    portal_ssl = PortalDaemon('portal_ssl','/var/run/smithproxy_portal_ssl.pid')
    #portal_ssl.should_chdir = False
    daemon.sub_daemons.append(portal_ssl)
    
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
                logging.info("starting daemons!")

                for d in daemon.sub_daemons:
                    print "starting " + d.nicename
                    p = os.fork()
                    if p == 0:
                        d.start()
                        print "finished " + d.nicename
            
                time.sleep(2)
                
                print "starting " + daemon.nicename                
                daemon.start()


        elif 'stop' == sys.argv[1]:
                logging.info("stopping daemons!")

                print "stopping " + daemon.nicename
                daemon.keeppid = False
                daemon.stop()
                time.sleep(5)
                
                for d in daemon.sub_daemons:
                    print "stopping " + d.nicename
                    d.stop()
                    

                
                
        elif 'restart' == sys.argv[1]:
                for d in daemon.sub_daemons:
                    print "restarting " + d.nicename
                    d.restart()
            
                daemon.restart()
                
        elif 'status' ==  sys.argv[1]:
                daemon.status(True,auto_restart=False)

        elif 'fix' ==  sys.argv[1] or 'repair' ==  sys.argv[1]:
                daemon.status(True,auto_restart=True)                
        else:
                print "Unknown command"
                sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
