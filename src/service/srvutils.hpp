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

#ifndef SRVUTILS_HPP_
#define SRVUTILS_HPP_

#include <policy/authfactory.hpp>

class ServiceFactory {
public:

    using proxy_type = threadedProxyWorker::proxy_type_t;

    static logan_lite& log() {
        static logan_lite l("service");
        return l;
    }

    template <class Listener, class Com>
    static Listener *
    prepare_listener (unsigned int port, std::string const &friendly_name, int sub_workers, proxy_type type);
    template <class Listener, class Com>
    static Listener* prepare_listener(std::string const& str_path, std::string const& friendly_name, std::string const& def_path, int sub_workers, proxy_type type);
};

template <class Listener, class Com>
Listener * ServiceFactory::prepare_listener (unsigned int port, std::string const &friendly_name, int sub_workers,
                                             proxy_type type) {

    auto log = ServiceFactory::log();

    if(sub_workers < 0) {
        return nullptr;
    }

    _not("Entering %s mode on port %d", friendly_name.c_str(), port);
    auto s_p = new Listener(new Com(), type);
    s_p->com()->nonlocal_dst(true);
    s_p->worker_count_preference(sub_workers);

    // bind with master proxy (.. and create child proxies for new connections)
    int s = s_p->bind(port,'L');
    if (s < 0) {
        _fat("Error binding %s port (%d), exiting", friendly_name.c_str(), s);
        delete s_p;
        return nullptr;
    };
    s_p->com()->unblock(s);
    
    s_p->com()->set_monitor(s);
    s_p->com()->set_poll_handler(s,s_p);

    return s_p;
}

template <class Listener, class Com>
Listener* ServiceFactory::prepare_listener(std::string const& str_path, std::string const& friendly_name, std::string const& def_path, int sub_workers, proxy_type type) {

    auto log = ServiceFactory::log();

    if(sub_workers < 0) {
        return nullptr;
    }
    
    std::string path = str_path;
    if( path.empty() ) {
        path = def_path;
    }
    
    _not("Entering %s mode on port %s",friendly_name.c_str(),path.c_str());
    auto s_p = new Listener(new Com(), type);
    s_p->com()->nonlocal_dst(true);
    s_p->worker_count_preference(sub_workers);

    // bind with master proxy (.. and create child proxies for new connections)
    int s = s_p->bind(path.c_str(),'L');
    if (s < 0) {
        _fat("Error binding %s port (%d), exiting",friendly_name.c_str(),s);
        delete s_p;
        return nullptr;
    };
    
    return s_p;
}


#endif