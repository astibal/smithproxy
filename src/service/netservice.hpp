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

#include <threadedacceptor.hpp>
#include <threadedreceiver.hpp>
#include <policy/authfactory.hpp>


namespace sx {
    class netservice_error : public std::runtime_error {
    public:
        explicit netservice_error (const char *string);
    };


    class netservice_cannot_bind : public netservice_error {
    public:
        explicit netservice_cannot_bind (const char *string);
    };
}

class NetworkServiceFactory {
public:

    using proxy_type = threadedProxyWorker::proxy_type_t;

    static logan_lite& log() {
        static logan_lite l("service");
        return l;
    }

    template <class Listener, class Com,
            typename port_type = unsigned short>
    static std::vector<Listener*> prepare_listener (port_type port, std::string const &friendly_name, int sub_workers,
                                                                    proxy_type type);
};

template <class Listener, class Com, typename port_type>
std::vector<Listener*> NetworkServiceFactory::prepare_listener (port_type port, std::string const &friendly_name, int sub_workers,
                                                    proxy_type type) {

    auto log = NetworkServiceFactory::log();

    std::vector<Listener*> vec_toret;

    if(sub_workers < 0) {
        // negative count means we won't spawn listeners for the service
        return vec_toret;
    }

    std::stringstream ss;
    ss << "Entering " << friendly_name << " mode on port/path " << port;
    auto sss = ss.str();

    _not(sss.c_str());

    auto create_listener = [&]() -> Listener* {
        auto r = new Listener(new Com(), type);
        r->com()->nonlocal_dst(true);
        r->worker_count_preference(sub_workers);

        return r;
    };



    auto attach_listener = [](Listener* r, int sock) {
        r->com()->unblock(sock);
        r->com()->set_monitor(sock);
        r->com()->set_poll_handler(sock, r);

    };

    auto listener = create_listener();

    // bind with master proxy (.. and create child proxies for new connections)
    int sock = listener->bind(port, 'L');

    locks::fd().insert(sock);

    auto l_ = std::scoped_lock(*locks::fd().lock(sock));

    if (sock < 0) {
        std::stringstream ss;
        ss << "error binding " << friendly_name << " on port/path: " << port;
        auto err = ss.str();

        _fat(err.c_str());
        delete listener;

        throw sx::netservice_cannot_bind(err.c_str());
    } else {

        // attach and push first listener
        attach_listener(listener, sock);

        vec_toret.push_back(listener);

        // create additional acceptor listeners (which will concurrently accept new connections)

        // how many?
        auto nthreads = std::thread::hardware_concurrency();
        nthreads *= listener->core_multiplier();

        if(sub_workers > 0)
            nthreads = sub_workers;


        nthreads = 2; // debug - create one addtional concurrent acceptor

        for(unsigned int i = 0; i < nthreads - 1 ; i++) {
            auto additional_listener = create_listener();

            if(additional_listener) {
                auto cx = additional_listener->listen(sock, 'L');
                if(! cx) {
                    throw sx::netservice_error("cannot create additional acceptor context");
                }

                vec_toret.push_back(additional_listener);
            }
            else {
                throw sx::netservice_error("cannot create additional acceptor");
            }

        }
    }

    return vec_toret;
}


#endif