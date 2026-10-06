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

#include <cstdio>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include <cstring>

#include <log/logger.hpp>
#include <service/daemon.hpp>
#include <display.hpp>

#ifndef BUILD_RELEASE

// use libunwind only in debug builds

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#endif

void DaemonFactory::set_tenant(const std::string& name, const std::string& tenant_id) {
    pid_file = string_format("/var/run/%s.%s.pid", name.c_str(), tenant_id.c_str());
}

// return 0 if returning as master, 1 if slave and ok, otherwise negative
int DaemonFactory::daemonize () {

    /* Our process ID and Session ID */
    pid_t pid, sid;

    _dia("daemonize start");

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
            _fat("daemonize: failed to fork!");

            return -1;
    }
    /* If we got a good PID, then
        we can exit the parent process. */
    if (pid > 0) {
            _dia("daemonize: exiting from master");

            return 0;
    } else {

        // if daemonizing, write pid file only from slave (master will be shut down)

        if(not write_pidfile()) {
            return -2;
        }
    }

    /* Change the file mode mask */
    umask(022);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
            /* Log the failure */
            _fat("daemonize: failed to setsid!");

            return -1;
    }



    /* Change the current working directory */
    if ((chdir("/")) < 0) {
            /* Log the failure */
            _fat("daemonize: failed to chdir to '/'!");

            return -1;
    }

    /* Close out the standard file descriptors */

    // don't ask me why we have to have opened stdin
    // close(STDIN_FILENO);

    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    _dia("daemonize: finished");

    return 1;
}

bool DaemonFactory::write_pidfile() {
    const int fd = ::open(pid_file.c_str(), O_WRONLY | O_CREAT | O_EXCL |
            O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0) {
        std::cerr << "cannot claim pid file: " << string_error() << std::endl;
        _err("cannot claim pid file: %s", string_error().c_str());
        return false;
    }

    const std::string pid = std::to_string(getpid());
    size_t offset = 0;
    int failure_errno = 0;
    while(offset < pid.size()) {
        const ssize_t written = ::write(fd, pid.data() + offset, pid.size() - offset);
        if(written > 0) {
            offset += static_cast<size_t>(written);
            continue;
        }
        if(written < 0 && errno == EINTR) {
            continue;
        }
        failure_errno = written == 0 ? EIO : errno;
        break;
    }

    const bool complete = offset == pid.size();
    const bool closed = ::close(fd) == 0;
    if(complete && closed) {
        pid_file_owned = true;
        return true;
    }

    if(complete && !closed) {
        failure_errno = errno;
    }
    ::unlink(pid_file.c_str());
    errno = failure_errno == 0 ? EIO : failure_errno;
    std::cerr << "cannot write pid file: " << string_error() << std::endl;
    _err("cannot write pid file: %s", string_error().c_str());
    return false;
}

void DaemonFactory::unlink_pidfile(bool force) {

    if(pid_file_owned || force) {
        if(unlink(pid_file.c_str()) != 0) {
            _err("cannot unlink pidfile: %s", string_error().c_str());
        } else {
            // success
            pid_file_owned = false;
        }
    }
}

bool DaemonFactory::exists_pidfile() const {
    struct stat st{};
    int result = stat(pid_file.c_str(), &st);
    return result == 0;
}

rlim_t DaemonFactory::get_limit_fd() {
    struct rlimit r{};
    int ret = getrlimit(RLIMIT_NOFILE, &r);
    if(ret < 0) {
        _err("get_limit_fd: cannot obtain fd limits: %s", string_error().c_str());
        return 0;
    }

    return r.rlim_cur;
}

void DaemonFactory::set_limit_fd(int max) {
    int n = max;
    if(max == 0) 
        n = 100000;

    struct rlimit r{};
    r.rlim_cur = n;
    r.rlim_max = 100000;
    
    int ret = setrlimit(RLIMIT_NOFILE,&r);

    if(ret < 0) {
        _err("set_limit_fd: cannot set fd limits: %s", string_error().c_str());
    }
}

void DaemonFactory::set_signal(int SIG, signal_handler_t sig_handler) {

    struct sigaction act_segv;
    memset(&act_segv, 0, sizeof(struct sigaction));

    sigemptyset(&act_segv.sa_mask);
    act_segv.sa_flags = 0;
    
    if(sig_handler != nullptr)  {
        act_segv.sa_handler = sig_handler;
    } else {
        act_segv.sa_handler = SIG_IGN;
    }
    
    sigaction( SIG, &act_segv, nullptr);
}


void DaemonFactory::set_crashlog(const char* file) {
    memset((void*)crashlog_file,0,LOG_FILENAME_SZ);
    if(file != nullptr) {
        strncpy((char*)crashlog_file,file,LOG_FILENAME_SZ-1);
    }
}

void writecrash(int fd, const char* msg, size_t len)  {

    if(len == 0 || fd < 0 || msg == nullptr) {
        return;
    }

   auto pos = msg;
   auto rest = len;

   while(rest > 0) {
       auto curw = ::write(fd, pos, rest);
       if(curw > 0) {
           pos = &pos[curw];
           rest -= static_cast<size_t>(curw);
           continue;
       }
       if(curw < 0 && errno == EINTR) {
           continue;
       }
       break;
   }
}

namespace {

int open_crashlog(const char* path) {
    const int fd = ::open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR);
    if(fd < 0) {
        return -1;
    }
    if(::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace


#ifndef BUILD_RELEASE

#ifdef USE_UNWIND
void DaemonFactory::uw_btrace_handler(int sig) {

    auto df = DaemonFactory::instance();

    if(DaemonFactory::generate_crashlog) {

        thread_local unw_cursor_t cursor;
        thread_local unw_context_t uc;
        thread_local unw_word_t ip;
        thread_local unw_word_t sp;

        unw_getcontext(&uc);
        unw_init_local(&cursor, &uc);

        constexpr size_t buf_line_sz = 1024;
        char buf_line[buf_line_sz] = {0};

        int chars = snprintf(buf_line, buf_line_sz, " ======== Smithproxy exception handler (sig %d) =========\n", sig);

        int CRLOG = open_crashlog((const char *) df->crashlog_file);
        if (CRLOG < 0) {
            return;
        }

        writecrash(STDERR_FILENO, buf_line, chars);
        writecrash(CRLOG, buf_line, chars);

        char time_buf[64] = {0};
        auto now = time(nullptr);
        ctime_r(&now, time_buf);
        chars = snprintf(buf_line, buf_line_sz, "Epoch time: %ld, localtime: %s\n", now, time_buf);

        writecrash(STDERR_FILENO, buf_line, chars);
        writecrash(CRLOG, buf_line, chars);

        writecrash(STDERR_FILENO, "Traceback:\n", 11);
        writecrash(CRLOG, "Traceback:\n", 11);

        while (unw_step(&cursor) > 0) {
            memset(buf_line, 0, buf_line_sz);

            char buf_fun[buf_line_sz];
            memset(buf_fun, 0, buf_line_sz);

            unw_word_t offset;
            unw_get_proc_name(&cursor, buf_fun, sizeof(buf_fun) - 1, &offset);
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            unw_get_reg(&cursor, UNW_REG_SP, &sp);

            chars = snprintf(buf_line, buf_line_sz, "ip = %lx, sp = %lx: (%s+0x%x) [%p]\n", (long) ip, (unsigned long) sp,
                             buf_fun, (unsigned int) offset, (void *) ip);

            writecrash(CRLOG, buf_line, chars);
            writecrash(STDERR_FILENO, buf_line, chars);
        }

        writecrash(STDERR_FILENO, " ===============================================\n", 50);
        writecrash(CRLOG, " ===============================================\n", 50);
        if (CRLOG >= 0) close(CRLOG);
    }

    df->unlink_pidfile();
    _exit(-1);
}
#endif // USE_UNWIND

#endif //BUILD_RELEASE

void DaemonFactory::release_crash_handler(int sig) {

    auto df = DaemonFactory::instance();

    if (DaemonFactory::generate_crashlog) {

        char buf_line[256];
        int chars = snprintf(buf_line, 255, " Error handler: signal %d received, aborting\n", sig);

        int CRLOG = open_crashlog((const char *) df->crashlog_file);
        if (CRLOG < 0) {
            return;
        }

        writecrash(STDERR_FILENO, buf_line, chars);
        writecrash(CRLOG, buf_line, chars);

        char time_buf[64] = {0};
        auto now = time(nullptr);
        ctime_r(&now, time_buf);
        chars = snprintf(buf_line, 255, "Epoch time: %ld, localtime: %s\n", now, time_buf);

        writecrash(STDERR_FILENO, buf_line, chars);
        writecrash(CRLOG, buf_line, chars);

        if (sig == 11 or sig == 6) {
            chars = snprintf(buf_line, 255, "  consider installing debug smithproxy version \n");
            writecrash(STDERR_FILENO, buf_line, chars);
            writecrash(CRLOG, buf_line, chars);
        }
        if (CRLOG >= 0) close(CRLOG);
    }

    df->unlink_pidfile();

#ifndef MEMPOOL_DISABLE
    memPool::bailing = true;
#endif
    _exit(-1);
}


void DaemonFactory::set_crash_signals() {

    void (*han)(int) = nullptr;

    #ifndef BUILD_RELEASE
        // even debug builds can disable unwind (release builds don't support unwind at all)
        #ifdef USE_UNWIND
            han = uw_btrace_handler;
        #else
            han = release_crash_handler;
        #endif
    #else
        han = release_crash_handler;
    #endif

    set_signal(SIGABRT, han);
    set_signal(SIGSEGV, han);
}

void DaemonFactory::set_daemon_signals(void (*terminate_handler)(int),void (*reload_handler)(int)) {
    // install signal handler, we do want to release the memory properly
        // signal handler installation
    
    set_signal(SIGTERM,terminate_handler);
    set_signal(SIGINT,terminate_handler);
    
    set_signal(SIGUSR1,reload_handler);
    set_signal(SIGPIPE, nullptr); // don't wake up threads on PIPE

    set_crash_signals();
}

std::string& DaemonFactory::class_name() const {
    static std::string s("DaemonFactory");
    return s;
}

std::string DaemonFactory::hr() const {
    return string_format("pidfile=(%s)", pid_file.c_str());
}
