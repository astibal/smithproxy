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


"""
    SmithDog:
    This is the maintenance/monitoring script keeping all smithproxy 
    components up and running.
    It's checking PID files, PIDs in them and if necessary, restarts 
    component if needed. It's very likely used by your init.d startup 
    script.
    It's not a good idea to mess with anything here, unless absolutely
    necessary.
    You can call this script yourself to see the status.
"""

import sys, time
from daemon import Daemon
import subprocess
import distutils
import logging
import os
import pprint


"""
   WARNING: this is not intended to be edited by end users !! 
"""

SMITHPROXY_PATH = '/usr/bin/smithproxy'
SMITHPROXY_PIDFILE = '/var/run/smithproxy.pid'

SMITHDOG_PIDFILE='/var/run/smithproxy_dog.pid'
SMITHDOG_LOGFILE='/var/log/smithproxy_dog.log'

WWW_PATH='/var/www/smithproxy/'
PORTAL_PATH=WWW_PATH+"portal/"
PORTAL_PIDFILE='/var/run/smithproxy_portal.pid'
PORTALSSL_PIDFILE='/var/run/smithproxy_portal_ssl.pid'

INFRA_PATH='/usr/share/smithproxy/infra/'
BEND_PIDFILE='/var/run/smithproxy_bend.pid'



sys.path.append(WWW_PATH)
sys.path.append(INFRA_PATH)

from portal import webfr
from bend   import bend

class PortalDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)

    def run(self):
        os.chdir(PORTAL_PATH)
        
        e = None
        logging.debug("PortalDaemon.run: starting "+self.nicename)
        if(self.nicename.endswith("ssl")):
            logging.info("PortalDaemon.run: starting ssl ("+self.nicename+")")
            e = webfr.run_portal_ssl()
        else:
            logging.info("PortalDaemon.run: starting plain ("+self.nicename+")")
            e = webfr.run_portal_plain()

        if(e):
            logging.error("portal finished with error: %s",str(e))
        else:
            logging.debug("portal finished...")

        time.sleep(1)
        sys.exit(1)


class BendDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)    
    def run(self):
        os.chdir(INFRA_PATH)
        bend.run_bend()


def start_exec(nicename, path, pidfile, additional_arguments=None):
    if(SmithProxyDog.check_running_pidfile(pidfile)):
        logging.info("process "+ nicename + "already running")
    else:
        opt = [path, '--daemonize']
        if additional_arguments:
            opt += additional_arguments

        r = subprocess.call(opt)        
        if r != 0:
            logging.error("process "+ nicename + " haven't stated!")
        else:
            logging.info("process " + nicename + " started correctly.")
            
def stop_exec(nicename,pidfile):
    Daemon.kill(pidfile)
    logging.info("process " + nicename + " terminated.")

class SmithProxyDog(Daemon):
    def __init__(self,poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'): 
        Daemon.__init__(self,'smithdog',SMITHDOG_PIDFILE,stdin,stdout,stderr)
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
                    msg = "fixing: " + nicename
                    logging.info(msg)
                    if print_stdout:
                        print msg

                    p = os.fork()
                    if p == 0:
                        start_exec(nicename,exe,pidfile)
                        sys.exit(0)
                    else:
                        logging.debug("fixing exec: parent process: %d waiting for %d to finish" % (os.getpid(),p) )
                        os.waitpid(p,1)   # wait for 'p'
                        logging.debug("fixing exec: parent process: %d waiting for %d finished" % (os.getpid(),p) )

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

                    # do restart in child. For all cases, child is just a temporary thing, so exit.
                    p = os.fork()
                    if p == 0:
                        logging.info("fixing sub-daemon: child process: %d" % (os.getpid(),) )
                        os.setsid()
                        d.daemonize()
                        d.run()
                        sys.exit(0)
                    else:
                        logging.debug("fixing sub-daemon: parent process: %d waiting for %d to finish" % (os.getpid(),p) )
                        os.waitpid(p,1)   # wait for 'p'
                        logging.debug("fixing sub-daemon: parent process: %d waiting for %d finished" % (os.getpid(),p) )


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
            err = str(e)
            if err.find("No such process") > 0:
                if os.path.exists(pidfile):
                    os.remove(pidfile)
                    logging.warning("Removing stale pidfile " + pidfile)

        return running


if __name__ == "__main__":
    logging.basicConfig(filename=SMITHDOG_LOGFILE, level=logging.INFO, format='%(asctime)s [%(process)d] %(message)s')

    daemon = SmithProxyDog(5)
    daemon.keeppid = True

    daemon.exec_info.append(('smithproxy core', SMITHPROXY_PATH, SMITHPROXY_PIDFILE))

    ### Backend INIT
    bend_ = BendDaemon('bend',BEND_PIDFILE)
    bend_.pwd = INFRA_PATH 
    daemon.sub_daemons.append(bend_)

    ### Portal INIT 

    portal_ = PortalDaemon('portal',PORTAL_PIDFILE)
    portal_.pwd = PORTAL_PATH
    daemon.sub_daemons.append(portal_)

    portal_ssl_ = PortalDaemon('portal_ssl',PORTALSSL_PIDFILE)
    portal_ssl_.pwd = PORTAL_PATH
    daemon.sub_daemons.append(portal_ssl_)

    if len(sys.argv) >= 2:
        if 'start' == sys.argv[1]:
                logging.info("starting daemons!")

                for d in daemon.sub_daemons:
                    print "starting " + d.nicename
                    p = os.fork()
                    if p == 0:
                        d.start()
                        print "finished " + d.nicename
                        sys.exit(0)
                    else:
                        os.waitpid(p,1)   # wait for 'p'

                for (n,e,p) in daemon.exec_info:
                    print "starting " + n
                    ppp = os.fork()
                    if ppp == 0:
                        start_exec(n,e,p)
                        print "finished " + n
                        sys.exit(0)
                    else:
                        os.waitpid(ppp,1)   # wait for 'p'

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
                    
                for (n,e,p) in daemon.exec_info:
                    print "stopping " + n
                    stop_exec(n,p)

        elif 'restart' == sys.argv[1]:
                for d in daemon.sub_daemons:
                    print "restarting " + d.nicename
                    d.restart()

                daemon.restart()

        elif 'status' ==  sys.argv[1]:
                daemon.status(True,auto_restart=False)

        elif 'fix' ==  sys.argv[1] or 'repair' ==  sys.argv[1]:
                daemon.status(True,auto_restart=True)
                
        elif 'test' == sys.argv[1]:
                if len(sys.argv) >= 3:
                    if 'bend' == sys.argv[2]:
                        bend_.run()
        else:
                print "Unknown command"
                sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
