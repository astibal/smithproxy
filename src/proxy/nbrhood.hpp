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

#include <socle/common/timeops.hpp>

#include <utils/lru.hpp>
#include <service/http/webhooks.hpp>

struct Neighbor {

    static constexpr size_t max_timetable_sz = 14;

    explicit Neighbor(std::string_view hostname): hostname(hostname) {
        last_seen = time(nullptr);
        timetable.reserve(max_timetable_sz+1);
    }

    using days_epoch_t = time_t;
    struct stats_entry_t {
        days_epoch_t days_epoch = epoch_days(time(nullptr));
        uint64_t counter = 0LL;

        // update entry with new data (currently only counter, which we know we inreasing by one)
        void update() {
            counter++;
        }

        [[nodiscard]] std::string to_string(int verbosity=iINF) const {
            std::stringstream ss;
            auto now_de = epoch_days(time(nullptr));
            ss << now_de - days_epoch << ":" << counter;
            return ss.str();
        }

        [[nodiscard]] nlohmann::json to_json() const {
            auto now_de = epoch_days(time(nullptr));

            return { now_de - days_epoch, counter };
        }
    };
    using stats_lists_t = std::vector<stats_entry_t>;

    void update() {
        last_seen = time(nullptr);
        auto this_de = epoch_days(last_seen);

        if(timetable.empty()) {
            timetable.emplace_back(stats_entry_t{ .days_epoch = this_de, .counter = 1 });
        } else {
            auto cur_de = timetable[0].days_epoch;
            if(cur_de == this_de) {
                timetable[0].update();
            }
            else {
                auto nev = stats_entry_t{ .days_epoch = this_de, .counter = 1 };
                timetable.insert(timetable.begin(), nev);

                if (timetable.size() > max_timetable_sz) {
                    timetable.pop_back();
                }
            }
        }
    }

    [[nodiscard]] nlohmann::json to_json() const {

        auto js = nlohmann::json();
        for(auto const& s: timetable)  {
            js.push_back(s.to_json());
        }

        return {
                { "hostname",  hostname },
                { "last_seen", last_seen },
                { "stats", js }
        };
    }

    [[nodiscard]] std::string to_string(int verbosity=iINF) const {

        std::stringstream ss;
        auto delta = time(nullptr) - last_seen;
        ss << hostname << " last seen: " << uptime_string(delta);
        if(not timetable.empty()) {
            ss << " stats:";
            for (auto const& entry: timetable) {
                ss << " " << entry.to_string(verbosity);
            }
        }
        return ss.str();
    }


    std::string hostname;
    time_t last_seen = 0L;
    stats_lists_t timetable {};
};

class NbrHood {
public:
    using nbr_t = std::shared_ptr<Neighbor>;
    using nbr_cache_t = LRUCache<std::string, nbr_t>;

    explicit NbrHood(size_t max_size): nbrs_(max_size) {}

    nbr_cache_t& cache() { return nbrs_; }
    nbr_cache_t const& cache() const { return nbrs_; }

    void update(Neighbor const& n) {
        auto lc_ = std::scoped_lock(cache().lock());

        if(auto nbr = cache().get_ul(n.hostname); nbr) {
            nbr.value()->update();
        }
        else {
            cache().put_ul(n.hostname, std::make_shared<Neighbor>(n));
            sx::http::webhooks::neighbor_new(n.hostname);
        }
    }

    [[nodiscard]] nlohmann::json to_json() const {
        auto lc_ = std::scoped_lock(cache().lock());

        auto ret = nlohmann::json();

        for(auto const& [ _, nbr]: cache().get_map_ul()) {
            ret.push_back( nbr.first->to_json());
        }

        return ret;
    }

    static NbrHood& instance() {
        static NbrHood r(1000);
        return r;
    }
private:
     nbr_cache_t nbrs_;
};