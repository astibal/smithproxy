#!/usr/bin/env python3

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

"""
    Originally taken from 
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    ... no licensing there. Thanks.
"""

import sys, os, time, atexit, io
import pwd, grp
from signal import SIGTERM 
from signal import SIGKILL
import logging
import signal


def create_logger(nickname, location):

    flog = logging.getLogger(nickname)
    hdlr = logging.FileHandler(location)
    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    flog.addHandler(hdlr) 
    flog.setLevel(logging.DEBUG)
    
    return flog

class Daemon:
    """
    A generic service class.
    
    Usage: subclass the Daemon class and override the run() method
    """
    log = create_logger("service", '/var/log/smithproxy_daemons.log')

    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.nicename = nicename
        self.should_chdir = True
        self.keeppid = False
        self.pwd = None

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced 
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                Daemon.log.debug(self.nicename + ": fork #1 master exit")
                sys.exit(0)


            Daemon.log.debug(self.nicename + ": fork #1 slave ok")
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            
        except OSError as e:
            Daemon.log.error(self.nicename + ": fork #1 failed: %d (%s)" % (e.errno, e.strerror))
            return False
    
        # decouple from parent environment
        try:
            if self.should_chdir:
                if not self.pwd:
                    os.chdir("/") 
                else:
                    os.chdir(self.pwd)
        except OSError as e:
            Daemon.log.error(self.nicename + ": fork #1 parameters problems: %d (%s)" % (e.errno, e.strerror))

        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                Daemon.log.debug(self.nicename + ": fork #2 master exit")
                sys.exit(0)
            Daemon.log.debug(self.nicename + ": fork #2 slave ok")
            Daemon.log.debug(self.nicename + ": service slave process ok")
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)

        except OSError as e:
            Daemon.log.error(self.nicename + ": fork #2 failed: %d (%s)" % (e.errno, e.strerror))
            return False
    
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = io.FileIO(self.stdin, 'r')
        so = io.FileIO(self.stdout, 'a+')
        se = io.FileIO(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())

        Daemon.log.debug("pid = %s", pid)

        with open(self.pidfile, "w+") as f:
            f.write("%s" % pid)
            
        # reset if this will be called again! 

        Daemon.log.debug(self.nicename + ": daemonize returning " + str(True))
        return True
    
    def delpid(self):
        if not self.keeppid:
            Daemon.log.info(self.nicename + ": removing pidfile " + self.pidfile)
            os.remove(self.pidfile)

    @staticmethod
    def readpid(fnm):
        # Check for a pidfile and the content
        pid = None
        try:
            pf = io.FileIO(fnm,'r')
            pid = int(pf.read().strip())
            pf.close()

        except FileNotFoundError as e:
            Daemon.log.debug("Daemon.readpid" + ": " +"cannot read pidfile: " + fnm + ": " + str(e))
            pid = None
        except IOError as e:
            Daemon.log.debug("Daemon.readpid" + ": " +"cannot read pidfile: " + fnm + ": " + str(e))
            pid = None
        except ValueError as e:
            Daemon.log.debug("Daemon.readpid" + ": " +"cannot read pidfile: " + fnm + ": " + str(e))
            pid = None   
            
        return pid

    def getpid(self):
        return Daemon.readpid(self.pidfile)

    def start(self):
        """
        Start the service
        """
        pid = self.getpid()
    
        if pid:
            message = "pidfile %s already exist. Daemon already running?"
            Daemon.log.error(self.nicename + ": " + message % self.pidfile)
            return False
        
        # Start the service
        if not self.daemonize():
            Daemon.log.error(self.nicename + ": " + "failed to daemonize, cannot run!")
            return False
            
        if not self.run():
            return False
        
        return True
        


    def stop(self):
        Daemon.kill(self.pidfile)

    @staticmethod
    def kill(pidfile):
        
        ret = False
        
        """
        Stop the service
        """
        # Get the pid from the pidfile
        try:
            pf = io.FileIO(pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
            ret = False
        except ValueError:
            pid = None
            ret = False

    
        if not pid:
            message = "pidfile %s does not exist. Daemon not running?"
            Daemon.log.error("kill: " + message % pidfile)
            return ret # not an error in a restart

        # Try killing the service process
        try:
            attempts = 0
            kill_attempts = 20 # wait 2 seconds, then send KILL
            while 1:
                sig = SIGTERM
                if attempts == kill_attempts:
                    Daemon.log.warning("trying to terminate with SIGKILL")
                    sig = SIGKILL
                    
                os.kill(pid, sig)
                time.sleep(0.1)
                attempts = attempts + 1
                
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(pidfile):
                    os.remove(pidfile)
                ret = True
            else:
                Daemon.log.error("cannot kill process at" + pidfile + ": " + str(err))
                ret = False
        return ret

    def is_running(self):
        try:
            pid = self.getpid()
            if pid:
                os.kill(pid, 0)
                return True
                
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
                return False
            else:
                return True
            
        return False

    def restart(self):
        """
        Restart the service
        """
        if self.is_running():
            self.stop()
            
        self.start()

    def run(self) -> bool:
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
        Daemon.log.info(self.nicename + ": default run routine!")
        return True

    def drop_privileges(self,uid_name='nobody', gid_name='nogroup'):
        if os.getuid() != 0:
            # We're not root so, like, whatever dude
            return

        # Get the uid/gid from the name
        running_uid = pwd.getpwnam(uid_name).pw_uid
        running_gid = grp.getgrnam(gid_name).gr_gid

        # Remove group privileges
        os.setgroups([])

        # Try setting the new uid/gid
        os.setgid(running_gid)
        os.setuid(running_uid)

        # Ensure a very conservative umask
        old_umask = os.umask(0o077)