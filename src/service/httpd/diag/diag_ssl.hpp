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

#include <nlohmann/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/util.hpp>
#include <service/http/jsonize.hpp>


static nlohmann::json json_ssl_cache_stats(struct MHD_Connection* conn, std::string const& meth, std::string const& req) {
    SSLFactory* store = SSLCom::factory();

    int n_cache = 0;
    int n_maxsize = 0;
    {
        std::lock_guard<std::recursive_mutex> l(store->lock());
        n_cache = store->cache_mitm().cache().size();
        n_maxsize = store->cache_mitm().max_size();
    }

    nlohmann::json ret = { { "cache_size", n_cache }, { "max_size",  n_maxsize } };
    return ret;
}

static nlohmann::json json_ssl_cache_print(struct MHD_Connection* connection, std::string const& meth, std::string const& req) {


    SSLFactory *store = SSLCom::factory();
    bool print_refs = false;

    int verbosity = connection_ll_param(connection, "verbosity", 6);
    nlohmann::json toret;

    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto const& x: store->cache_mitm().cache()) {
            std::string fqdn = x.first;
            auto chain = x.second->ptr()->entry();

            nlohmann::json detail;

            auto name_vec = string_split(fqdn, '+');
            detail["subject"] = name_vec[0];
            detail["names"] = name_vec;

            if(print_refs) {
                int counter = x.second->count();
                int age = x.second->age();

                detail["usage"] = {
                        "accessed",  counter,
                        "age", age
                    };
            }

            detail[fqdn] =  jsonize::from(chain.chain.cert, verbosity);
            toret.push_back(detail);
        }
    }

    if(toret.empty()) return nlohmann::json::array();
    return toret;
}


