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
#include <socle/common/stringops.hpp>

#include <utils/lru.hpp>
#include <service/http/webhooks.hpp>

struct Neighbor {

    static inline logan_lite log = logan_lite("proxy.nbr");
    static inline size_t max_timetable_sz = 30;

    explicit Neighbor(std::string_view hostname): hostname(hostname) {
        last_seen = time(nullptr);
        timetable.reserve(max_timetable_sz+1);
    }

    using days_epoch_t = time_t;
    struct stats_entry_t {
        days_epoch_t days_epoch = epoch_days(time(nullptr));
        uint64_t counter = 1LL;

        uint64_t bytes_up {0};
        uint64_t bytes_down {0};

        std::set<std::string, std::less<std::string>> labels {};

        // update entry with new data (currently only counter, which we know we are increasing by one)
        void update() {
            counter++;
        }

        [[nodiscard]] std::string to_string(int verbosity=iINF) const {
            std::stringstream ss;
            auto now_de = epoch_days(time(nullptr));
            ss << now_de - days_epoch << ":" << counter;

            if(bytes_up + bytes_down > 0)
                ss << "(up:" << bytes_up << ",dw:" << bytes_down << ")";
            if(not labels.empty()) {
                ss << "+(";
                for (auto const &l: labels)
                    ss << "+" << l;
                ss << ")";
            }
            return ss.str();
        }

        [[nodiscard]] nlohmann::json to_json() const {
            auto now_de = epoch_days(time(nullptr));

            nlohmann::json ret = { { "relative_days", now_de - days_epoch },
                     { "counter", counter },
                     { "bytes_up", bytes_up },
                     { "bytes_down", bytes_down },
            };

            for(auto const& l: labels)
                ret["labels"].push_back(l);

            return ret;
        }

        [[nodiscard]] nlohmann::json ser_json_out() const {
            nlohmann::json ret = { { "days_epoch", days_epoch },
                     { "counter", counter},
                     { "bytes_up", bytes_up },
                     { "bytes_down", bytes_down },
            };

            for(auto const& l: labels)
                ret["labels"].push_back(l);

            return ret;
        }

        void ser_json_in(nlohmann::json const& j) {
            try {
                days_epoch = j["days_epoch"];
                counter = j["counter"];

                if(j.contains("bytes_up"))
                    bytes_up = j["bytes_up"];

                if(j.contains("bytes_down"))
                    bytes_down = j["bytes_down"];

                if(j.contains("labels")) {
                    labels.clear();
                    for(auto const& jj: j["labels"]) {
                        labels.insert(jj.get<std::string>());
                    }
                }
            }
            catch(nlohmann::json::exception const& e) {
                Log::get()->events().insert(ERR, "stat_entry::ser_json_in: %s", e.what());
                _err("stat_entry::ser_json_in: %s", e.what());
            }
        }

    };
    using stats_lists_t = std::vector<stats_entry_t>;

    void update() {
        last_seen = time(nullptr);
        auto this_de = epoch_days(last_seen);

        if(timetable.empty()) {
            _dia("neighbor update: %s: new timetable entry", hostname.c_str());
            timetable.emplace_back();
        } else {
            auto cur_de = timetable[0].days_epoch;
            if(cur_de == this_de) {
                _dia("neighbor update: %s: update today timetable", hostname.c_str());
                timetable[0].update();
            }
            else {
                _dia("neighbor update: %s: add today timetable", hostname.c_str());
                auto nev = stats_entry_t();
                timetable.insert(timetable.begin(), nev);

                while (timetable.size() > max_timetable_sz) {
                    _dia("neighbor update: %s: removing excess timetable entry", hostname.c_str());
                    timetable.pop_back();
                }
            }
        }
    }

    [[nodiscard]] nlohmann::json ser_json_out() const {
        auto js = nlohmann::json();
        for(auto const& s: timetable)  {
            js.push_back(s.ser_json_out());
        }

        return {
                { "hostname",  hostname },
                { "last_seen", last_seen },
                { "tags", tags_to_string() },
                { "stats", js }
        };
    }

    void ser_json_in(nlohmann::json const& j) {

        try {
            hostname = j.at("hostname").get<std::string>();
            last_seen = j.at("last_seen").get<time_t>();
            if(j.contains("tags")) {
                tags = string_tags(j.at("tags").get<std::string>());
            }

            auto raw_stats = j.at("stats").get<std::vector<nlohmann::json>>();
            timetable.clear();
            for (const auto &rs: raw_stats) {
                Neighbor::stats_entry_t entry;
                entry.ser_json_in(rs);
                timetable.push_back(entry);
            }
        }
        catch(nlohmann::json::exception const& e) {
            Log::get()->events().insert(ERR, "neighbor::ser_json_in: %s", e.what());
            _err("neighbor::ser_json_in: %s", e.what());
        }
    }


    [[nodiscard]] nlohmann::json to_json() const {

        auto js = nlohmann::json();
        for(auto const& s: timetable)  {
            js.push_back(s.to_json());
        }

        return {
                { "hostname",  hostname },
                { "tags", tags_to_string() },
                { "last_seen", last_seen },
                { "stats", js }
        };
    }

    [[nodiscard]] std::string to_string(int verbosity=iINF) const {

        std::stringstream ss;
        auto delta = time(nullptr) - last_seen;

        ss << hostname;
        if(not tags.empty())
            ss << " tags: " << tags_to_string();
        ss << " last seen: " << uptime_string(delta);
        if(not timetable.empty()) {
            ss << " stats:";
            for (auto const& entry: timetable) {
                ss << " " << entry.to_string(verbosity);
            }
        }
        return ss.str();
    }

    // make a single string of tags, separated by `+`
    [[nodiscard]] std::string tags_to_string() const {
        return std::accumulate(tags.begin(), tags.end(), std::string(),
                               [](std::string const& a, std::string const& b) {
                                   return a + (a.length() > 0 ? "+" : "") + b;
                               });
    }

    // update tags with an update string:
    // `+` - adds the tag
    // `-` - removes the tag
    // `=` - removes all tags
    //
    // Examples:
    // ```
    // tags_update("+abc"); // adds 'abc' tag
    // tags_update("-abc"); // removes 'abc' tag
    // tags_update("=+yyy+xxx") // tags are reset and contain only 'yyy' and 'xxx' tags
    //```
    void tags_update(std::string const& update_string) {
        string_tags_update(tags, update_string);
    }

    std::string hostname;
    time_t last_seen = 0L;
    stats_lists_t timetable {};
    std::vector<std::string> tags;
};

class NbrHood {
public:
    using nbr_t = std::shared_ptr<Neighbor>;
    using nbr_cache_t = LRUCache<std::string, nbr_t>;

    explicit NbrHood(size_t max_size): nbrs_(max_size) {}

    nbr_cache_t& cache() { return nbrs_; }
    nbr_cache_t const& cache() const { return nbrs_; }

    void update(std::string const& hostname) {
        bool is_new = false;
        {
            auto lc_ = std::scoped_lock(cache().lock());
            if (auto nbr = cache().get_ul(hostname); nbr) {
                nbr.value()->update();
            } else {
                auto ptr = std::make_shared<Neighbor>(hostname);
                ptr->update();
                cache().put_ul(hostname, ptr);
                is_new = true;
            }
        }

        // send a new neighbor only if we actually create one
        if(is_new)
            sx::http::webhooks::neighbor_new(hostname);
    }

    bool apply(std::string const& hostname, std::function<bool(Neighbor&)> mod) {
        auto lc_ = std::scoped_lock(cache().lock());

        if(auto nbr = cache().get_ul(hostname); nbr) {
            return mod(*nbr.value());
        }
        else {
            auto ptr = std::make_shared<Neighbor>(hostname);
            cache().put_ul(hostname, ptr);
            return mod(*ptr);
        }

    }

    void for_each(std::function<void(Neighbor&)> mod) {
        auto lc_ = std::scoped_lock(cache().lock());
        for(auto& item: cache().get_map_ul()) {
            mod(*item.second.first);
        }
    }

    [[nodiscard]] nlohmann::json to_json() const {
        return to_json([](auto const&) { return true;});
    }

    [[nodiscard]] nlohmann::json to_json(std::function<bool(Neighbor const&)> const& filter) const {
        auto lc_ = std::scoped_lock(cache().lock());

        auto ret = nlohmann::json();

        for(auto const& [ _, nbr]: cache().get_map_ul()) {
            if(filter(*nbr.first))
                ret.push_back( nbr.first->to_json());
        }

        return ret;
    }

    [[nodiscard]] nlohmann::json ser_json_out() const {
        auto lc_ = std::scoped_lock(cache().lock());

        auto ret = nlohmann::json();

        for(auto const& [ _, nbr]: cache().get_map_ul()) {
            ret.push_back( nbr.first->ser_json_out());
        }

        return ret;
    }

    void ser_json_in(nlohmann::json const& j) {
        auto lc_ = std::scoped_lock(cache().lock());

        try {
            if (!j.is_array())
                return;

            for (const auto &raw_neighbor: j) {
                auto nbr = std::make_shared<Neighbor>("");
                nbr->ser_json_in(raw_neighbor);
                cache().put_ul(nbr->hostname, nbr);
            }
        }
        catch(nlohmann::json::exception const& e) {
            auto const& log = Neighbor::log;
            _err("nbrhood::ser_json_in: %s", e.what());
        }
    }

    static NbrHood& instance() {
        static NbrHood r(4000);
        return r;
    }
private:
     nbr_cache_t nbrs_;
};