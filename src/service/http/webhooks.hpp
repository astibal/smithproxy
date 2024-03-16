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


#ifndef SX_HTTP_WEBHOOKS
#define SX_HTTP_WEBHOOKS

#include <string>
#include <atomic>
#include <nlohmann/json.hpp>
#include <service/http/async_request.hpp>

namespace sx::http::webhooks {

    struct url_stats {
        std::string url;
        int total_counter = 0;
        int error_counter = 0;
    };

    std::mutex& url_stats_lock();
    std::unordered_map<std::string, url_stats>& url_stats_map();

    void ping();
    void set_enabled(bool val);
    bool is_enabled();
    void set_hostid(std::string const& ref);

    void neighbor_new(std::string const& address_str);
    void send_action(std::string const& action, std::string const& action_id, nlohmann::json const& details);
    void send_action_wait(std::string const& action, std::string const& action_id, nlohmann::json const& details, sx::http::AsyncRequest::reply_hook hook);
}

#endif