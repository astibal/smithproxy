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

#ifndef TESTFILTER_HPP
#define TESTFILTER_HPP

#include <proxy/filters/filterproxy.hpp>
#include <nlohmann/json.hpp>

class SinkholeFilter : public FilterProxy {

public:
    bool sink_left = false;
    bool sink_right = false;
    std::string replacement;

    uint64_t left_sunken = 00L;
    uint64_t right_sunken = 00L;

    SinkholeFilter() = default;
    // which received data should be sunken? If left, data from left are not sent to the right side
    SinkholeFilter(MitmProxy* parent, bool sink_left, bool sink_right) : FilterProxy(parent), sink_left(sink_left), sink_right(sink_right) {}

    std::string to_string(int verbosity) const override {
        return string_format("Sinkhole-L%d-R%d%s, sunken %ld:%ld", sink_left, sink_right, replacement.empty() ? "" : "-repl", left_sunken, right_sunken);
    }

    nlohmann::json to_json(int verbosity) const override {
        auto ret = nlohmann::json();
        ret["sink_left"] = sink_left;
        ret["sink_right"] = sink_right;
        ret["sunken_left"] = left_sunken;
        ret["sunken_right"] = right_sunken;
        ret["replacement_size"] = replacement.size();

        return ret;
    }

    void proxy(baseHostCX *from, baseHostCX *to, socle::side_t side, bool redirected) override;

private:
    static inline logan_lite log {"proxy.sinkhole"};
};

#endif