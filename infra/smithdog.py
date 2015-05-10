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

LOG_OK_INTERVAL = 60


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
            logging.debug("PortalDaemon.run: Starting https portal")
            self.drop_privileges()
            e = webfr.run_portal_ssl()
        else:
            logging.debug("PortalDaemon.run: Starting http portal")
            self.drop_privileges()
            e = webfr.run_portal_plain()

        if(e):
            logging.error("PortalDaemon.run: finished with error: %s",str(e))
        else:
            logging.debug("PortalDaemon.run: finished...")

        time.sleep(1)
        sys.exit(1)


class BendDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)    
    def run(self):
        os.chdir(INFRA_PATH)
        #self.drop_privileges() # not ready for this yet
        bend.run_bend()


def start_exec(nicename, path, pidfile, additional_arguments=None):
    if(SmithProxyDog.check_running_pidfile(pidfile)):
        logging.info("process "+ nicename + "already running")
    else:
        opt = [path, '--daemonize']
        if additional_arguments:
            opt += additional_arguments

        logging.debug("start_exec: Starting " + nicename )
        r = subprocess.call(opt)
        if r != 0:
            logging.error("start_exec: finished with error: %d" % (r,))
        else:
            logging.debug("start_exec: finished...")
            
def stop_exec(nicename,pidfile):
    Daemon.kill(pidfile)
    logging.debug("process " + nicename + " terminated.")

class SmithProxyDog(Daemon):
    def __init__(self,poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'): 
        Daemon.__init__(self,'smithdog',SMITHDOG_PIDFILE,stdin,stdout,stderr)
        self.exec_info = []     # tuples of nicename,executable,pidfile_of_executable
        self.sub_daemons = []   # daemons which we are starting via Daemon class interface
        self.poll_interval = poll_interval
        self.last_ok_log = 0

    def should_log_ok(self):
        if time.time() - self.last_ok_log > LOG_OK_INTERVAL:
            # it's time to print/log OK status
            self.last_ok_log  = time.time()
            return True
        return False
    
    # this will be needed to reset if the status was not OK => we should print out OK then immediatelly
    def reset_log_ok(self):
        self.last_ok_log = 0

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
                    logging.warning(msg)
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
                    msg = "fixing: " + d.nicename
                    logging.info(msg)
                    if print_stdout:
                        print msg

                    # do restart in child. For all cases, child is just a temporary thing, so exit.
                    p = os.fork()
                    if p == 0:
                        logging.debug("fixing sub-daemon: child process: %d" % (os.getpid(),) )
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
            if self.should_log_ok():
                logging.info(msg)
                
            if print_stdout:
                # stdout printing is not dependent on counters
                print msg
        else:
            self.reset_log_ok()

        return ret

    def run(self):
        while True:
            self.status(False)
            time.sleep(self.poll_interval)

    @staticmethod
    def print_process_status(r,nicename,print_stdout=False):
            statmsg = "NOT running"
            prep = "WARNING: "
            if r:
                statmsg = "running"
                prep = ''
            if not print_stdout:
                if not r:
                    logging.warning("Status of '" + nicename + "': " + statmsg)  
                else:
                    logging.info("Status of '" + nicename + "': " + statmsg)  
            else:
                print prep + "Status of '" + nicename + "': " + statmsg

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
    logging.basicConfig(filename=SMITHDOG_LOGFILE, level=logging.INFO, format='%(asctime)s [%(process)d] [%(levelname)s] %(message)s')

    daemon = SmithProxyDog(0.5)
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
                logging.info("STARTING ALL DAEMONS!")
                print "STARTING ALL DAEMONS!"

                for d in daemon.sub_daemons:
                    logging.info("Starting " + d.nicename)
                    p = os.fork()
                    if p == 0:
                        d.start()
                        #logging.info("  finished ")
                        sys.exit(0)
                    else:
                        os.waitpid(p,1)   # wait for 'p'

                for (n,e,p) in daemon.exec_info:
                    logging.info("Starting " + n)
                    ppp = os.fork()
                    if ppp == 0:
                        start_exec(n,e,p)
                        #logging.info("  finished")
                        sys.exit(0)
                    else:
                        os.waitpid(ppp,1)   # wait for 'p'

                time.sleep(2)

                logging.info("Starting " + daemon.nicename)
                daemon.start()
                #logging.info("  finished")

                daemon.status(True,auto_restart=False)

        elif 'stop' == sys.argv[1]:
                wait_time = 3
                logging.info("STOPPING ALL DEAMONS!")
                print "STOPPING ALL DEAMONS!"

                logging.info("Stopping " + daemon.nicename + " (wait "+str(wait_time)+"s)")
                daemon.keeppid = False
                daemon.stop()
                time.sleep(wait_time)
                #logging.info("  finished")

                for d in daemon.sub_daemons:
                    logging.info("Stopping " + d.nicename)
                    d.stop()
                    #logging.info("  finished")

                for (n,e,p) in daemon.exec_info:
                    logging.info("Stopping " + n)
                    stop_exec(n,p)
                    #logging.info("  finished")

                daemon.status(True,auto_restart=False)


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
        print "usage: %s start|stop|status|fix" % sys.argv[0]
        sys.exit(2)
