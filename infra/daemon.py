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
    Originally taken from 
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    ... no licensing there. Thanks.
"""

import sys, os, time, atexit
import pwd, grp
from signal import SIGTERM 
import logging
import signal

class Daemon:
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    """
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
                logging.info(self.nicename + ": fork #1 master exit")
                sys.exit(0)

                
            logging.info(self.nicename + ": fork #1 slave ok")
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            
        except OSError, e: 
            logging.error(self.nicename + ": fork #1 failed: %d (%s)" % (e.errno, e.strerror))
            return False
    
        # decouple from parent environment
        try:
            if self.should_chdir:
                if not self.pwd:
                    os.chdir("/") 
                else:
                    os.chdir(self.pwd)
        except OSError, e: 
            logging.error(self.nicename + ": fork #1 parameters problems: %d (%s)" % (e.errno, e.strerror))

        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                logging.info(self.nicename + ": fork #2 master exit")
                sys.exit(0) 
            logging.info(self.nicename + ": fork #2 slave ok")
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)

        except OSError, e: 
            logging.error(self.nicename + ": fork #2 failed: %d (%s)" % (e.errno, e.strerror))
            return False
    
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s" % pid)
            
        # reset if this will be called again! 
        
        logging.info(self.nicename + ": daemonize returning " + str(True))
        return True
    
    def delpid(self):
        if not self.keeppid:
            logging.info(self.nicename + ": removing pidfile " + self.pidfile)
            os.remove(self.pidfile)

    @staticmethod
    def readpid(fnm):
        # Check for a pidfile and the content
        pid = None
        try:
            pf = file(fnm,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError,e:
            logging.debug("Daemon.readpid" + ": " +"cannot read pidfile: " + fnm + ": " + str(e))
            pid = None   
        except ValueError,e:
            logging.debug("Daemon.readpid" + ": " +"cannot read pidfile: " + fnm + ": " + str(e))
            pid = None   
            
        return pid

    def getpid(self):
        return Daemon.readpid(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        pid = self.getpid()
    
        if pid:
            message = "pidfile %s already exist. Daemon already running?"
            logging.error(self.nicename + ": " + message % self.pidfile)
            return
        
        # Start the daemon
        if not self.daemonize():
            logging.error(self.nicename + ": " + "failed to daemonize, cannot run!")
            return
            
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        except ValueError:
            pid = None

    
        if not pid:
            message = "pidfile %s does not exist. Daemon not running?"
            logging.error(self.nicename + ": " + message % self.pidfile)
            return # not an error in a restart

        # Try killing the daemon process    
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                return

    def is_running(self):
        try:
            os.kill(pid, 0)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
                return False
            else:
                return True

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
        logging.info(self.nicename + ": default run routine!")

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
        old_umask = os.umask(077)