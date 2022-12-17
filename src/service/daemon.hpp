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

#ifndef DAEMON_HPP
#define DAEMON_HPP
#include <sys/resource.h>

#include <string>
#include <log/logan.hpp>

#define PID_FILE_DEFAULT "/var/run/smithproxy.default.pid"
#define LOG_FILENAME_SZ 512


struct DaemonFactory : public LoganMate {

    using signal_handler_t = void(*)(int);

    std::string pid_file = PID_FILE_DEFAULT;
    volatile char crashlog_file[LOG_FILENAME_SZ];
    bool pid_file_owned = false;

    [[nodiscard]] std::string &class_name() const override;
    [[nodiscard]] std::string hr() const override;

    static std::shared_ptr<DaemonFactory> instance() {
        static std::shared_ptr<DaemonFactory> d = std::make_shared<DaemonFactory>();
        return d;
    }
    void set_tenant(const std::string& name, const std::string& tenant_id);

    int daemonize ();
    bool write_pidfile();
    bool exists_pidfile() const;
    void unlink_pidfile(bool force = false);
    rlim_t get_limit_fd();
    void set_limit_fd(int max);
    static void set_signal(int SIG, void (*sig_handler)(int));
    static void set_crash_signals();
    static void set_daemon_signals(void (*terminate_handler)(int),void (*reload_handler)(int));
    void set_crashlog(const char* file);

#ifndef BUILD_RELEASE
    static void uw_btrace_handler(int sig);
#endif

    static void release_crash_handler(int sig);

    DaemonFactory(DaemonFactory const&) = delete;
    DaemonFactory& operator=(DaemonFactory const&) = delete;
    virtual ~DaemonFactory() { unlink_pidfile(); }

    DaemonFactory() {
        ::memset((void*)crashlog_file, 0, LOG_FILENAME_SZ);
    }

    static inline bool generate_crashlog = true;

    logan_lite& get_log() { return log; };
private:
    logan_lite log {"service"};

    TYPENAME_BASE("DaemonFactory")
};



#endif