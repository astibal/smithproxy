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

#include <ext/json/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/util.hpp>
#include <service/httpd/jsonize.hpp>


static nlohmann::json json_proxy_session_list(struct MHD_Connection * connection) {

    std::scoped_lock<std::recursive_mutex> l_(socle::sobjectDB::getlock());

    nlohmann::json ret;

    bool flag_active_only = connection_ll_param(connection, "active", 0) > 0;
    bool flag_tlsinfo = connection_ll_param(connection, "tlsinfo", 0) > 0;
    int verbosity = connection_ll_param(connection, "verbosity", iINF);


    auto json_single_proxy = [&](MitmProxy* proxy) -> std::optional<nlohmann::json> {
        if(flag_active_only) {
            if(proxy->stats().mtr_up.get() == 0L and proxy->stats().mtr_down.get() == 0L)
                return std::nullopt;
        }

        if(proxy->lsize() == 0 or proxy->rsize() == 0) {
            return std::nullopt;
        }

        auto proxy_detail = jsonize::from(proxy, verbosity);

        if(flag_tlsinfo) {
            nlohmann::json left;
            nlohmann::json right;

            if(proxy->first_left()) {
                left = jsonize::from(proxy->first_left()->com(), verbosity);
            }
            if(proxy->first_right()) {
                right = jsonize::from(proxy->first_right()->com(), verbosity);
            }

            proxy_detail["tlsinfo"] = { { "left", left },
                                        { "right", right }
            };
        }
        return proxy_detail;
    };


    auto oid = connection_ull_param(connection, "oid", 0ULL);
    if(oid != 0ULL) {
        auto it = socle::sobjectDB::oid_db().find(oid);
        if(it != socle::sobjectDB::oid_db().end()) {

            std::string what = it->second->c_type();
            if (what == "MitmProxy" || what == "SocksProxy") {
                auto *proxy = dynamic_cast<MitmProxy *>(it->second.get());
                if (proxy) {
                    auto single_ret = json_single_proxy(proxy);
                    if (single_ret.has_value()) ret.push_back(single_ret.value());
                    return ret;
                }
            }
        }
        return nlohmann::json::array();
    } else {

        auto& sx = SmithProxy::instance();

        auto list_worker = [&json_single_proxy, &ret](const char* title, auto& listener) {
            for (auto acc: listener) {
                for(auto wrk: acc->tasks()) {

                    {
                        auto l_ = std::scoped_lock(wrk.second->proxy_lock());

                        for(auto& [ p, thr ] : wrk.second->proxies()) {
                            if(auto* proxy = dynamic_cast<MitmProxy*>(p.get()); p != nullptr) {
                                auto single_ret = json_single_proxy(proxy);
                                if (single_ret.has_value()) {
                                    single_ret.value()["origin"] = title;
                                    ret.push_back(single_ret.value());
                                }
                            }
                        }
                    }
                }
            }
        };

        list_worker("plain acceptor", sx.plain_proxies);
        list_worker("tls acceptor", sx.ssl_proxies);

        list_worker("udp receiver", sx.udp_proxies);
        list_worker("dtls receiver", sx.dtls_proxies);

        list_worker("socks acceptor", sx.socks_proxies);

        list_worker("plain redirect acceptor", sx.redir_plain_proxies);
        list_worker("dns redirect receiver", sx.redir_udp_proxies);
        list_worker("tls redirect acceptor", sx.redir_ssl_proxies);

        if (ret.empty()) return nlohmann::json::array();

        return ret;
    }
}