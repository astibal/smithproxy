/*
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
    
*/    


#include <sys/types.h>
#include <sys/stat.h>
#include <csignal>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <logger.hpp>
#include <daemon.hpp>
#include <display.hpp>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#ifdef __cplusplus
extern "C" {
#endif

std::string PID_FILE(PID_FILE_DEFAULT);

void daemon_set_tenant(const std::string& tenant_id) {
    PID_FILE = string_format("/var/run/smithproxy.%s.pid",tenant_id.c_str());
}

void daemonize(void) {
        
    /* Our process ID and Session ID */
    pid_t pid, sid;
    
    DIAS_("daemonize start");
    
    struct stat st;
    if( stat(PID_FILE.c_str(),&st) == 0) {
        ERRS_("There seems to be smithproxy already running in the system. Aborting.");
        exit(EXIT_FAILURE);
    }
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
            FATS_("daemonize: failed to fork!");
            exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then
        we can exit the parent process. */
    if (pid > 0) {
            DIAS_("daemonize: exiting from master");
            exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(022);
            
    /* Open any logs here */        
            
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
            /* Log the failure */
            FATS_("daemonize: failed to setsid!");
            exit(EXIT_FAILURE);
    }
    

    
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
            /* Log the failure */
            FATS_("daemonize: failed to chdir to '/'!");
            exit(EXIT_FAILURE);
    }
    
    /* Close out the standard file descriptors */
    
    // don't ask me why we have to have opened stdin
    // close(STDIN_FILENO);
    
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
        
    DIAS_("daemonize: finished");
}

void daemon_write_pidfile() {
    FILE* pf = fopen(PID_FILE.c_str(),"w");
    fprintf(pf,"%d",getpid());
    fclose(pf);
}

void daemon_unlink_pidfile() {
    unlink(PID_FILE.c_str());
}

bool daemon_exists_pidfile() {
    struct stat st;
    int result = stat(PID_FILE.c_str(), &st);
    return result == 0;
}

int daemon_get_limit_fd() {
    struct rlimit r;
    int ret = getrlimit(RLIMIT_NOFILE,&r);
    if(ret < 0) {
        ERR_("daemon_get_limit_fd: cannot obtain fd limits: %s", string_error().c_str());
        return -1;
    }

    return r.rlim_cur;
}

void daemon_set_limit_fd(int max) {
    int n = max;
    if(max == 0) 
        n = 100000;

    struct rlimit r;
    r.rlim_cur = n;
    r.rlim_max = 100000;
    
    int ret = setrlimit(RLIMIT_NOFILE,&r);

    if(ret < 0) {
        ERR_("daemon_set_limit_fd: cannot set fd limits: %s", string_error().c_str());
    }
}

void daemon_signals(void (*segv_handler)(int)) {
    struct sigaction act_segv;
    sigemptyset(&act_segv.sa_mask);
    act_segv.sa_flags = 0;
    
    if(segv_handler != nullptr)  act_segv.sa_handler = segv_handler;
    
    sigaction( SIGSEGV, &act_segv, NULL);
}


#ifdef __cplusplus
}
#endif
