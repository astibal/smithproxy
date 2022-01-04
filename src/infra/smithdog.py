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

import os
import subprocess
import sys
import time


"""
   WARNING: this is not intended to be edited by end users !! 
"""

TENANT_NAME = "default"
TENANT_IDX = "0"

SMITHPROXY_PATH = '/usr/bin/smithproxy'
SMITHPROXY_PIDFILE = '/var/run/smithproxy.%s.pid'

SMITHD_PATH = '/usr/bin/smithd'
SMITHD_PIDFILE = '/var/run/smithd.%s.pid'

SMITHDOG_PIDFILE = '/var/run/smithproxy_dog.%s.pid'
SMITHDOG_LOGFILE = '/var/log/smithproxy/dog.%s.log'

WWW_PATH = '/usr/share/smithproxy/www/'
PORTAL_PATH = WWW_PATH + "portal/"
PORTAL_PIDFILE = '/var/run/smithproxy_portal.%s.pid'
PORTALSSL_PIDFILE = '/var/run/smithproxy_portal_ssl.%s.pid'

INFRA_PATH = '/usr/share/smithproxy/infra/'
BEND_PIDFILE = '/var/run/smithproxy_bend.%s.pid'
BENDBROD_PIDFILE = '/var/run/smithproxy_bendbrod.%s.pid'

WOTD_PIDFILE = '/var/run/smithproxy_wotd.pid'
WOTD_SOCKFILE = '/var/run/smithproxy_wotd-socket'

LOG_OK_INTERVAL = 60

sys.path.append(WWW_PATH)
sys.path.append(INFRA_PATH)

HAVE_AUTH = False

from daemon import Daemon, create_logger
from uxserv import ThreadedUxServerDaemon

try:
    from portal import webfr
    from bend import bend
    from bend import bendbrod
    from bend.wot import wotresponder

    HAVE_AUTH = True

except ImportError as e:
    pass


global flog


class PortalDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self, nicename, pidfile, stdin, stdout, stderr)

    def run(self) -> bool:
        global TENANCY, TENANT_IDX, TENANT_NAME
        os.chdir(PORTAL_PATH)

        ret_code = None
        flog.debug("PortalDaemon.run: starting " + self.nicename)

        if self.nicename.endswith("ssl"):
            flog.debug("PortalDaemon.run: Starting https portal")
            # e = webfr.run_portal_ssl(TENANT_NAME,TENANT_IDX,self.drop_privileges) # -- it breaks cgi-bin scripts logging
            ret_code = webfr.run_portal_ssl(TENANT_NAME, TENANT_IDX)

        else:
            flog.debug("PortalDaemon.run: Starting http portal")
            # e = webfr.run_portal_plain(TENANT_NAME,TENANT_IDX,self.drop_privileges) -- it breaks cgi-bin scripts logging
            ret_code = webfr.run_portal_plain(TENANT_NAME, TENANT_IDX)

        if ret_code:
            flog.error("PortalDaemon.run: finished with error: %s", str(ret_code))
            return False
        else:
            flog.debug("PortalDaemon.run: finished...")

        time.sleep(1)
        sys.exit(1)


class BendDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self, nicename, pidfile, stdin, stdout, stderr)

    def run(self) -> bool:
        global TENANT_NAME, TENANT_IDX

        os.chdir(INFRA_PATH)
        # self.drop_privileges() # not ready for this yet

        flog.info("DOG => BEND: tenant=%s index=%s" % (TENANT_NAME, TENANT_IDX))
        print("DOG => BEND: tenant=%s index=%s" % (TENANT_NAME, TENANT_IDX))

        try:
            bend.run_bend(tenant_name=TENANT_NAME, tenant_index=TENANT_IDX)
        except Exception as e:
            flog.info("bend: failure during execution: %s" % (str(e)))
            print("Failure during execution: %s" % (str(e)))

            return False

        return True


class BendBrodDaemon(Daemon):
    def __init__(self, nicename, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self, nicename, pidfile, stdin, stdout, stderr)

    def run(self) -> bool:
        global TENANT_NAME, TENANT_IDX

        os.chdir(INFRA_PATH)
        # self.drop_privileges() # not ready for this yet

        flog.info("DOG => BENDBROD: tenant=%s index=%s" % (TENANT_NAME, TENANT_IDX))
        try:
            b = bendbrod.BendBroker(TENANT_IDX, TENANT_NAME)
            b.run()
        except Exception as e:
            flog.info("bendbrod: failure during execution: %s" % (str(e)))
            return  False

        return True


def start_exec(nicename, path, pidfile, additional_arguments=None):

    if SmithProxyDog.check_running_pidfile(pidfile):
        flog.info("process " + nicename + "already running")

    else:
        opt = [path, '--daemonize']
        if additional_arguments:
            opt += additional_arguments

        flog.debug("start_exec: Starting " + nicename)
        r = subprocess.call(opt)
        if r != 0:
            flog.error("start_exec: finished with error: %d" % (r,))
        else:
            flog.debug("start_exec: finished...")


def stop_exec(nicename, pidfile):
    Daemon.kill(pidfile)
    flog.debug("process " + nicename + " terminated.")


class SmithProxyDog(Daemon):
    def __init__(self, poll_interval=0.2, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        Daemon.__init__(self, 'smithdog', SMITHDOG_PIDFILE % (TENANT_NAME,), stdin, stdout, stderr)
        self.exec_info = []  # tuples of nicename,executable,pidfile_of_executable
        self.sub_daemons = []  # daemons which we are starting via Daemon class interface
        self.startup = True
        self.poll_interval = poll_interval
        self.last_ok_log = 0

    def should_log_ok(self):
        if time.time() - self.last_ok_log > LOG_OK_INTERVAL:
            # it's time to print/log OK status
            self.last_ok_log = time.time()
            return True
        return False

    # this will be needed to reset if the status was not OK => we should print out OK then immediately
    def reset_log_ok(self):
        self.last_ok_log = 0

    def status(self, print_stdout=False, auto_restart=True, print_nice=False):

        ret = True
        r = SmithProxyDog.check_running_pidfile(self.pidfile)
        if not r:
            SmithProxyDog.print_process_status(r, self.nicename, print_stdout, print_nice=print_nice)
            ret = r
            if auto_restart:
                msg = "Cannot automatically fix myself: please run the 'start' parameter"
                flog.error(msg)
                if print_stdout:
                    print(msg)

        for (nicename, exe, pidfile, add) in self.exec_info:
            r = SmithProxyDog.check_running_pidfile(pidfile)
            if not r:
                SmithProxyDog.print_process_status(r, nicename, print_stdout=print_stdout, print_nice=print_nice)
                ret = r
                if auto_restart:
                    msg = "fixing: " + nicename
                    flog.warning(msg)
                    if print_stdout:
                        print(msg)

                    p = os.fork()
                    if p == 0:
                        start_exec(nicename, exe, pidfile, add)
                        sys.exit(0)
                    else:
                        flog.debug("fixing exec: parent process: %d waiting for %d to finish" % (os.getpid(), p))
                        os.waitpid(p, 1)  # wait for 'p'
                        flog.debug("fixing exec: parent process: %d waiting for %d finished" % (os.getpid(), p))

        for d in self.sub_daemons:
            r = SmithProxyDog.check_running_pidfile(d.pidfile)
            if not r:
                SmithProxyDog.print_process_status(r, d.nicename, print_stdout=print_stdout, print_nice=print_nice)
                ret = r
                if auto_restart:
                    msg = "fixing: " + d.nicename
                    flog.info(msg)
                    if print_stdout:
                        print(msg)

                    # do restart in child. For all cases, child is just a temporary thing, so exit.
                    p = os.fork()
                    if p == 0:
                        flog.debug("fixing sub-daemon: child process: %d" % (os.getpid(),))
                        os.setsid()
                        d.daemonize()
                        d.run()
                        sys.exit(0)
                    else:
                        flog.debug("fixing sub-daemon: parent process: %d waiting for %d to finish" % (os.getpid(), p))
                        os.waitpid(p, 1)  # wait for 'p'
                        flog.debug("fixing sub-daemon: parent process: %d waiting for %d finished" % (os.getpid(), p))

        if ret:
            msg = "Status of all monitored processes is OK"
            if self.should_log_ok():
                flog.info(msg)

            if print_stdout:
                # stdout printing is not dependent on counters
                print(msg)
        else:
            self.reset_log_ok()

        return ret

    def run(self) -> bool:

        self.startup = True

        while True:
            try:

                if self.startup:
                    time.sleep(5*self.poll_interval)
                    self.startup = False

                self.status(False)
                time.sleep(self.poll_interval)
            except Exception as e:
                flog.error("SmithProxyDog: exception in main loop: %s" % str(e))
                break

        return True

    @staticmethod
    def print_process_status(r, nicename, print_stdout=False, print_nice=False):

        if print_nice:

            statmsg_ok = "started"
            statmsg_nok = "stopped"
            prep = "  "
        else:
            statmsg_ok = "running"
            statmsg_nok = "NOT running"
            prep = ""

        if r:
            msg = ("%-17s : " % (nicename,)) + statmsg_ok
        else:
            msg = ("%-17s : " % (nicename,)) + statmsg_nok

        if not print_stdout:
            if not r:
                flog.warning(msg)
            else:
                flog.info(msg)
        else:
            print(msg)

    @staticmethod
    def check_running_pidfile(pidfile):

        flog.debug("Checking pidfile " + pidfile)

        running = False
        try:
            pid = Daemon.readpid(pidfile)
            if pid > 0:
                flog.debug("Checking pidfile " + pidfile + " found pid " + str(pid))
                os.kill(pid, 0)
                running = True
                flog.debug("Checking pidfile " + pidfile + " found pid " + str(pid) + " running")

            elif pid == 0:
                flog.debug("Checking pidfile " + pidfile + ": unknown value, but running")
                running = True
            else:
                flog.debug("Checking pidfile " + pidfile + " no pid found")


        except OSError as e:
            flog.debug("Checking pidfile " + pidfile + " found pid :" + str(e))
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

    flog = create_logger("dog", SMITHDOG_LOGFILE % (TENANT_NAME,))

    daemon = SmithProxyDog(1)
    daemon.keeppid = True

    smithproxy_options = []

    smithproxy_options.append("--tenant-name")
    smithproxy_options.append(TENANT_NAME)
    smithproxy_options.append("--tenant-index")
    smithproxy_options.append(TENANT_IDX)

    daemon.exec_info.append(
        ('smithproxy core', SMITHPROXY_PATH, SMITHPROXY_PIDFILE % (TENANT_NAME,), smithproxy_options))

    daemon.exec_info.append(('smithproxy smithd', SMITHD_PATH, SMITHD_PIDFILE % (TENANT_NAME,), smithproxy_options))


    bend_ = None
    bendbrod_ = None

    portal_ = None
    portal_ssl_ = None

    wotd_ = None

    if HAVE_AUTH:

        # Backend INIT
        bend_ = BendDaemon('bend', BEND_PIDFILE % (TENANT_NAME,))
        bend_.pwd = INFRA_PATH
        bend_.log = flog
        daemon.sub_daemons.append(bend_)

        # Backend broker daemon -- unprivileged connections from clients
        bendbrod_ = BendBrodDaemon('bendbrod', BENDBROD_PIDFILE % (TENANT_NAME,))
        bendbrod_.pwd = INFRA_PATH
        bendbrod_.log = flog
        daemon.sub_daemons.append(bendbrod_)

        # Portal INIT

        portal_ = PortalDaemon('portal', PORTAL_PIDFILE % (TENANT_NAME,))
        portal_.pwd = PORTAL_PATH
        portal_.log = flog
        daemon.sub_daemons.append(portal_)

        portal_ssl_ = PortalDaemon('portal_ssl', PORTALSSL_PIDFILE % (TENANT_NAME,))
        portal_ssl_.pwd = PORTAL_PATH
        portal_ssl_.log = flog
        daemon.sub_daemons.append(portal_ssl_)

        wotd_ = ThreadedUxServerDaemon("wotd", WOTD_PIDFILE, WOTD_SOCKFILE, wotresponder.WotResponder)
        wotd_.pwd = "/var/run/"
        wotd_.log = flog
        daemon.sub_daemons.append(wotd_)

    if len(sys.argv) >= 2:

        if 'start' == sys.argv[1]:
            flog.info("starting all daemons")
            print("Starting all daemons")

            for d in daemon.sub_daemons:
                flog.info("Starting " + d.nicename)
                p = os.fork()
                if p == 0:
                    r = d.start()

                    if not r:
                        flog.error("  error occurred")
                    else:
                        flog.info("  finished ")
                    sys.exit(0)
                else:
                    os.waitpid(p, 1)  # wait for 'p'

            for (n, e, p, a) in daemon.exec_info:
                flog.info("Starting " + n)
                ppp = os.fork()
                if ppp == 0:
                    start_exec(n, e, p, a)
                    # flog.info("  finished")
                    sys.exit(0)
                else:
                    os.waitpid(ppp, 1)  # wait for 'p'


            flog.info("Starting " + daemon.nicename)
            daemon.start()
            # flog.info("  finished")

            daemon.status(True, auto_restart=False)

        elif 'stop' == sys.argv[1]:

            flog.info("stopping all daemons")
            print("stopping all daemons\n")

            flog.info("  stopping " + daemon.nicename)
            daemon.keeppid = False
            daemon.stop()

            for d in daemon.sub_daemons:
                flog.info("  stopping " + d.nicename)
                d.stop()
                # flog.info("  finished")

            for (n, e, p, a) in daemon.exec_info:
                flog.info("  stopping " + n)
                stop_exec(n, p)
                # flog.info("  finished")

            daemon.status(print_stdout=True, auto_restart=False, print_nice=True)

        elif 'status' == sys.argv[1]:
            daemon.status(True, auto_restart=False)

        elif 'fix' == sys.argv[1] or 'repair' == sys.argv[1]:
            daemon.status(True, auto_restart=True)

        elif 'test' == sys.argv[1]:
            if len(sys.argv) >= 3:
                if 'bend' == sys.argv[2] and bend_:
                    bend_.start()
                if 'portal_plain' == sys.argv[2] and portal_:
                    portal_.start()
                if 'portal_ssl' == sys.argv[2] and portal_ssl_:
                    portal_ssl_.start()
                elif HAVE_AUTH:
                    flog.error("cannot perform this operation on: " + sys.argv[2])
                elif not HAVE_AUTH:
                    flog.error("components not present")



        # run them in the foreground (avoid Daemon.start() invocation)
        elif 'run' == sys.argv[1]:
            if len(sys.argv) >= 3:
                if 'bend' == sys.argv[2] and bend_:
                    bend_.run()
                if 'portal_plain' == sys.argv[2] and portal_:
                    portal_.run()
                if 'portal_ssl' == sys.argv[2] and portal_ssl_:
                    portal_ssl_.run()
                elif HAVE_AUTH:
                    flog.error("cannot perform this operation on: " + sys.argv[2])
                elif not HAVE_AUTH:
                    flog.error("components not present")

        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        print("usage: %s start|stop|status|fix" % sys.argv[0])
        sys.exit(2)
