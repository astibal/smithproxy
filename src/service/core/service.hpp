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


#ifndef SMITHPROXY_SERVICE_HPP
#define SMITHPROXY_SERVICE_HPP

#include <string>
#include <atomic>

#include <common/log/logan.hpp>

class Service {

protected:

    explicit Service() : tenant_index_(0), tenant_name_("default"), log(service_log()) {

        self() = this;

        log.level(WAR);
        reload_handler_ = my_usr1;
        terminate_handler_ = my_terminate;

        ts_sys_started = ::time(nullptr);
    }
    unsigned int tenant_index_;
    std::string  tenant_name_;

public:

    // flag for threads which don't have mechanics to terminate themselves
    std::atomic<bool> terminate_flag {false};
    std::atomic<bool> terminated {false};

    [[nodiscard]] static bool abort_sleep(unsigned int steps, unsigned int step=1);

    unsigned int tenant_index () const { return tenant_index_; }
    void tenant_index (unsigned int tenantIndex) { tenant_index_ = tenantIndex; }

    const std::string& tenant_name () const { return tenant_name_;  }
    void tenant_name (const std::string &tenantName) { tenant_name_ = tenantName;  }

    bool cfg_daemonize = false;
    std::time_t ts_sys_started{0};


    void (*terminate_handler_)(int) = nullptr;
    void (*reload_handler_)(int) = nullptr;

    logan_lite& log;
    static logan_lite& service_log() { static logan_lite log = logan_lite("service"); return log; }


    // "self" static variable is set by Service c-tor (there could be just one "self" at a time)
    static Service*& self() { static Service* s(nullptr); return s; };
    static void my_terminate(int param);
    static void my_usr1 (int param);
    void set_handler_term(void (*terminate_handler)(int)) { terminate_handler_ = terminate_handler;  }
    void set_handler_reload(void (*reload_handler)(int)) { reload_handler_ = reload_handler; }

    volatile int cnt_terminate = 0;

    virtual void run() = 0;
    virtual void stop() = 0;
    virtual void reload() = 0;
};

#endif //SMITHPROXY_SERVICE_HPP
