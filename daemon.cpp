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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include <logger.hpp>
#include <daemon.hpp>

#ifdef __cplusplus
extern "C" {
#endif

#define PID_FILE "/var/run/smithproxy"
    
void daemonize(void) {
        
    /* Our process ID and Session ID */
    pid_t pid, sid;
    
    DIAS_("daemonize start");
    
    struct stat st;
    if( stat("/var/run/smithproxy",&st) == 0) {
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
    
    /* Daemon-specific initialization goes here */
    
    daemon_write_pidfile();
    
    DIAS_("daemonize: finished");
}

void daemon_write_pidfile() {
    FILE* pf = fopen(PID_FILE,"w");
    fprintf(pf,"%d",getpid());
    fclose(pf);
}

void daemon_unlink_pidfile() {
    unlink(PID_FILE);
}

#ifdef __cplusplus
}
#endif
