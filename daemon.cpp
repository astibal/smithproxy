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
#include <execinfo.h>

#include <logger.hpp>
#include <daemon.hpp>
#include <display.hpp>

#define UNW_LOCAL_ONLY
#include <libunwind.h>


void DaemonFactory::set_tenant(const std::string& name, const std::string& tenant_id) {
    PID_FILE = string_format("/var/run/%s.%s.pid",name.c_str(), tenant_id.c_str());
}

void DaemonFactory::daemonize() {
        
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

void DaemonFactory::write_pidfile() {
    FILE* pf = fopen(PID_FILE.c_str(),"w");
    fprintf(pf,"%d",getpid());
    fclose(pf);
}

void DaemonFactory::unlink_pidfile() {
    unlink(PID_FILE.c_str());
}

bool DaemonFactory::exists_pidfile() {
    struct stat st;
    int result = stat(PID_FILE.c_str(), &st);
    return result == 0;
}

int DaemonFactory::get_limit_fd() {
    struct rlimit r;
    int ret = getrlimit(RLIMIT_NOFILE,&r);
    if(ret < 0) {
        ERR_("get_limit_fd: cannot obtain fd limits: %s", string_error().c_str());
        return -1;
    }

    return r.rlim_cur;
}

void DaemonFactory::set_limit_fd(int max) {
    int n = max;
    if(max == 0) 
        n = 100000;

    struct rlimit r;
    r.rlim_cur = n;
    r.rlim_max = 100000;
    
    int ret = setrlimit(RLIMIT_NOFILE,&r);

    if(ret < 0) {
        ERR_("set_limit_fd: cannot set fd limits: %s", string_error().c_str());
    }
}

void DaemonFactory::set_signal(unsigned int SIG, void (*sig_handler)(int)) {
    struct sigaction act_segv;
    sigemptyset(&act_segv.sa_mask);
    act_segv.sa_flags = 0;
    
    if(sig_handler != nullptr)  act_segv.sa_handler = sig_handler;
    
    sigaction( SIG, &act_segv, nullptr);
}


void DaemonFactory::set_crashlog(const char* file) {
    memset((void*)crashlog_file,0,LOG_FILENAME_SZ);
    strncpy((char*)crashlog_file,file,LOG_FILENAME_SZ-1);
}

void DaemonFactory::uw_btrace_handler(int sig) {
    thread_local unw_cursor_t cursor; 
    thread_local unw_context_t uc;
    thread_local unw_word_t ip;
    thread_local unw_word_t sp;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    DaemonFactory& df = DaemonFactory::instance();

    char buf_line[256];
    int chars = snprintf(buf_line,255," ======== Smithproxy exception handler (sig %d) =========\n",sig);

    int CRLOG = open((const char*)df.crashlog_file, O_CREAT | O_WRONLY | O_TRUNC,S_IRUSR|S_IWUSR);
    write(STDERR_FILENO,buf_line,chars);
    write(CRLOG,buf_line,chars);
    write(STDERR_FILENO,"Traceback:\n",11);
    write(CRLOG,"Traceback:\n",11);

    while (unw_step(&cursor) > 0) {
        memset(buf_line,0,256);
        char buf_fun[256];
        memset(buf_fun,0,256);

        unw_word_t  offset;
        unw_get_proc_name(&cursor, buf_fun, sizeof(buf_fun), &offset);
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        
        int chars = snprintf(buf_line, 255, "ip = %lx, sp = %lx: (%s+0x%x) [%p]\n", (long) ip, (unsigned long) sp, buf_fun, (unsigned int) offset, (void*)ip);

        write(CRLOG,buf_line,chars);
        write(STDERR_FILENO,buf_line,chars);
    }
    
    write(STDERR_FILENO," ===============================================\n",50);
    write(CRLOG," ===============================================\n",50);
    close(CRLOG);

    df.unlink_pidfile();
    
    exit(-1);
}

void DaemonFactory::set_daemon_signals(void (*terminate_handler)(int),void (*reload_handler)(int)) {
    // install signal handler, we do want to release the memory properly
        // signal handler installation
    
    set_signal(SIGTERM,terminate_handler);
    set_signal(SIGINT,terminate_handler);
    
    set_signal(SIGUSR1,reload_handler);
    
    set_signal(SIGABRT,uw_btrace_handler);
    set_signal(SIGSEGV,uw_btrace_handler);
}

