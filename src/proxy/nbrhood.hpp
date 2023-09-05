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

#include <string>
#include <unordered_map>
#include <memory>
#include <ctime>
#include <nlohmann/json.hpp>

#include <utils/lru.hpp>
#include <service/http/async_request.hpp>

struct Neighbor {
    Neighbor(std::string_view hostname): hostname(hostname), last_seen(time(nullptr)) {}

    std::string hostname;
    time_t last_seen;

    void update() {
        last_seen = time(nullptr);
    }
};

class NbrHood {
public:
    using nbr_t = std::shared_ptr<Neighbor>;
    using nbr_cache_t = LRUCache<std::string, nbr_t>;

    explicit NbrHood(size_t max_size): nbrs_(max_size) {}

    nbr_cache_t& cache() { return nbrs_; }
    void update(Neighbor const& n) {
        auto lc_ = std::scoped_lock(cache().lock());

        if(auto nbr = cache().get_ul(n.hostname); nbr) {
            nbr.value()->update();
        }
        else {
            nlohmann::json const nbr_update = { { "action", "neighbor.new" }, { "address", n.hostname } };
            sx::http::AsyncRequest::emit(
                    to_string(nbr_update),
                    [](auto reply){});
            cache().put_ul(n.hostname, std::make_shared<Neighbor>(n));
        }
    }

    static NbrHood& instance() {
        static NbrHood r(1000);
        return r;
    }
private:
     nbr_cache_t nbrs_;
};