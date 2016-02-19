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
from daemon import Daemon,create_logger
import subprocess
import distutils
import logging
import os
import pprint


"""
   WARNING: this is not intended to be edited by end users !! 
"""
global TENANCY, TENANT_IDX, TENANT_NAME

TENANCY = False
TENANT_NAME = "default"
TENANT_IDX = "0"

SMITHPROXY_PATH = '/usr/bin/smithproxy'
SMITHPROXY_PIDFILE = '/var/run/smithproxy.%s.pid'

SMITHDOG_PIDFILE='/var/run/smithproxy_dog.%s.pid'
SMITHDOG_LOGFILE='/var/log/smithproxy_dog.%s.log'

WWW_PATH='/usr/share/smithproxy/www/'
PORTAL_PATH=WWW_PATH+"portal/"
PORTAL_PIDFILE='/var/run/smithproxy_portal.%s.pid'
PORTALSSL_PIDFILE='/var/run/smithproxy_portal_ssl.%s.pid'

INFRA_PATH='/usr/share/smithproxy/infra/'
BEND_PIDFILE='/var/run/smithproxy_bend.%s.pid'

WOTD_PIDFILE='/var/run/smithproxy_wotd.pid'
WOTD_SOCKFILE='/var/run/smithproxy_wotd-socket'

LOG_OK_INTERVAL = 60


sys.path.append(WWW_PATH)
sys.path.append(INFRA_PATH)

from portal import webfr
from bend   import bend
from bend.wot   import wotresponder
from uxserv import ThreadedUxServerDaemon,Responder_OK

global flog

class PortalDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)

    def run(self):
        global TENANCY,TENANT_IDX,TENANT_NAME
        os.chdir(PORTAL_PATH)
        
        e = None
        flog.debug("PortalDaemon.run: starting "+self.nicename)
        if(self.nicename.endswith("ssl")):
            flog.debug("PortalDaemon.run: Starting https portal")
            self.drop_privileges()
            e = webfr.run_portal_ssl(TENANT_NAME,TENANT_IDX)
        else:
            flog.debug("PortalDaemon.run: Starting http portal")
            self.drop_privileges()
            e = webfr.run_portal_plain(TENANT_NAME,TENANT_IDX)

        if(e):
            flog.error("PortalDaemon.run: finished with error: %s",str(e))
        else:
            flog.debug("PortalDaemon.run: finished...")

        time.sleep(1)
        sys.exit(1)


class BendDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self,nicename,pidfile,stdin,stdout,stderr)    
    def run(self):
        os.chdir(INFRA_PATH)
        #self.drop_privileges() # not ready for this yet
        
        flog.info("DOG => BEND: tenant=%s index=%s" % (TENANT_NAME,TENANT_IDX))
        bend.run_bend(tenant_name=TENANT_NAME,tename_index=TENANT_IDX)


def start_exec(nicename, path, pidfile, additional_arguments=None):
    if(SmithProxyDog.check_running_pidfile(pidfile)):
        flog.info("process "+ nicename + "already running")
    else:
        opt = [path, '--daemonize']
        if additional_arguments:
            opt += additional_arguments

        flog.debug("start_exec: Starting " + nicename )
        r = subprocess.call(opt)
        if r != 0:
            flog.error("start_exec: finished with error: %d" % (r,))
        else:
            flog.debug("start_exec: finished...")
            
def stop_exec(nicename,pidfile):
    Daemon.kill(pidfile)
    flog.debug("process " + nicename + " terminated.")

class SmithProxyDog(Daemon):
    def __init__(self,poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'): 
        Daemon.__init__(self,'smithdog',SMITHDOG_PIDFILE % (TENANT_NAME,),stdin,stdout,stderr)
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
                flog.error(msg)
                if print_stdout:
                    print msg



        for (nicename,exe,pidfile,add) in self.exec_info:
            r = SmithProxyDog.check_running_pidfile(pidfile)
            if not r: 
                SmithProxyDog.print_process_status(r,nicename,print_stdout)
                ret = r
                if auto_restart:
                    msg = "fixing: " + nicename
                    flog.warning(msg)
                    if print_stdout:
                        print msg

                    p = os.fork()
                    if p == 0:
                        start_exec(nicename,exe,pidfile,add)
                        sys.exit(0)
                    else:
                        flog.debug("fixing exec: parent process: %d waiting for %d to finish" % (os.getpid(),p) )
                        os.waitpid(p,1)   # wait for 'p'
                        flog.debug("fixing exec: parent process: %d waiting for %d finished" % (os.getpid(),p) )

        for d in self.sub_daemons:
            r = SmithProxyDog.check_running_pidfile(d.pidfile)
            if not r: 
                SmithProxyDog.print_process_status(r,d.nicename,print_stdout)        
                ret = r
                if auto_restart:                
                    msg = "fixing: " + d.nicename
                    flog.info(msg)
                    if print_stdout:
                        print msg

                    # do restart in child. For all cases, child is just a temporary thing, so exit.
                    p = os.fork()
                    if p == 0:
                        flog.debug("fixing sub-daemon: child process: %d" % (os.getpid(),) )
                        os.setsid()
                        d.daemonize()
                        d.run()
                        sys.exit(0)
                    else:
                        flog.debug("fixing sub-daemon: parent process: %d waiting for %d to finish" % (os.getpid(),p) )
                        os.waitpid(p,1)   # wait for 'p'
                        flog.debug("fixing sub-daemon: parent process: %d waiting for %d finished" % (os.getpid(),p) )


        if ret:
            msg = "Status of all monitored processes is OK"
            if self.should_log_ok():
                flog.info(msg)
                
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
                    flog.warning("Status of '" + nicename + "': " + statmsg)  
                else:
                    flog.info("Status of '" + nicename + "': " + statmsg)  
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
                    flog.warning("Removing stale pidfile " + pidfile)

        return running


if __name__ == "__main__":

    if len(sys.argv) >= 4:
        TENANCY = True
        TENANT_NAME = sys.argv[2]
        TENANT_IDX = sys.argv[3]
        
    flog = create_logger("dog",SMITHDOG_LOGFILE % (TENANT_NAME,))
        
    daemon = SmithProxyDog(0.5)
    daemon.keeppid = True

    smithproxy_options = []
    if TENANCY:
        smithproxy_options.append("--tenant-name")
        smithproxy_options.append(TENANT_NAME)
        smithproxy_options.append("--tenant-index")
        smithproxy_options.append(TENANT_IDX)
        
    daemon.exec_info.append(('smithproxy core', SMITHPROXY_PATH, SMITHPROXY_PIDFILE % (TENANT_NAME,), smithproxy_options ))

    ### Backend INIT
    bend_ = BendDaemon('bend',BEND_PIDFILE % (TENANT_NAME,))
    bend_.pwd = INFRA_PATH 
    daemon.sub_daemons.append(bend_)

    ### Portal INIT 

    portal_ = PortalDaemon('portal',PORTAL_PIDFILE % (TENANT_NAME,))
    portal_.pwd = PORTAL_PATH
    daemon.sub_daemons.append(portal_)

    portal_ssl_ = PortalDaemon('portal_ssl',PORTALSSL_PIDFILE % (TENANT_NAME,))
    portal_ssl_.pwd = PORTAL_PATH
    daemon.sub_daemons.append(portal_ssl_)


    wotd_ = ThreadedUxServerDaemon("wotd",WOTD_PIDFILE,WOTD_SOCKFILE,wotresponder.WotResponder)
    wotd_.pwd = "/var/run/"
    daemon.sub_daemons.append(wotd_)

    if len(sys.argv) >= 2:
        
        
        if 'start' == sys.argv[1]:
                flog.info("STARTING ALL DAEMONS!")
                print "STARTING ALL DAEMONS!"

                for d in daemon.sub_daemons:
                    flog.info("Starting " + d.nicename)
                    p = os.fork()
                    if p == 0:
                        d.start()
                        #flog.info("  finished ")
                        sys.exit(0)
                    else:
                        os.waitpid(p,1)   # wait for 'p'

                for (n,e,p,a) in daemon.exec_info:
                    flog.info("Starting " + n)
                    ppp = os.fork()
                    if ppp == 0:
                        start_exec(n,e,p,a)
                        #flog.info("  finished")
                        sys.exit(0)
                    else:
                        os.waitpid(ppp,1)   # wait for 'p'

                time.sleep(2)

                flog.info("Starting " + daemon.nicename)
                daemon.start()
                #flog.info("  finished")

                daemon.status(True,auto_restart=False)

        elif 'stop' == sys.argv[1]:
                wait_time = 3
                flog.info("STOPPING ALL DEAMONS!")
                print "STOPPING ALL DEAMONS!"

                flog.info("Stopping " + daemon.nicename + " (wait "+str(wait_time)+"s)")
                daemon.keeppid = False
                daemon.stop()
                time.sleep(wait_time)
                #flog.info("  finished")

                for d in daemon.sub_daemons:
                    flog.info("Stopping " + d.nicename)
                    d.stop()
                    #flog.info("  finished")

                for (n,e,p,a) in daemon.exec_info:
                    flog.info("Stopping " + n)
                    stop_exec(n,p)
                    #flog.info("  finished")

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
