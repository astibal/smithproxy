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



#ifndef FILTER_PROXY
 #define FILTER_PROXY
 
#include <ctime>

#include "sobject.hpp"
#include "common/display.hpp"
#include "src/proxy/mitmproxy.hpp"
#include <nlohmann/json.hpp>

struct FilterResult : public socle::sobject {
    // NONE - Send some data
    // WANT_MORE_LEFT -  asking for more LEFT bytes before we can FINISH
    // WANT_MORE_RIGHT - asking for more RIGHT bytes before we can FINISH
    // FINISHED_OK   - filtering has been finished. Don't send anything more. Proxy as needed.
    // FINISHED_DROP - filtering has been finished. Don't send anything more, data considered as harmful, drop parent proxy.
    using status_flags = enum { NONE=0x0000, WANT_MORE_LEFT=0x0002, WANT_MORE_RIGHT=0x0004, FINISHED_DROP=0x0008, FINISHED_OK=0x8000 } ;
    uint64_t status_ = NONE;

    bool is_flag(status_flags sf) const { return flag_check<uint64_t>(&status_,(uint64_t )sf); };
    void set_flag(status_flags sf) { flag_set<uint64_t >(&status_,(uint64_t )sf); }

    std::string to_string(int verbosity) const override { static std::string r("FilterResult"); return r; };
    bool ask_destroy() override { return false; };
};

class FilterProxy : public socle::sobject {
public:
    
    FilterProxy() = default;
    explicit FilterProxy(MitmProxy* parent) : parent_(parent) {};
    ~FilterProxy() override = default;

    virtual void update_states() {
        // some filters need extra non-const steps before calling to_string() const
        // we don't need to override, empty is just fine
    };
    std::string to_string(int verbosity) const override { static std::string r("FilterProxy"); return r; };
    virtual nlohmann::json to_json(int verbosity) const { return nlohmann::json(); };

    bool ask_destroy() override;

    virtual void proxy(baseHostCX* from, baseHostCX* to, side_t side, bool redirected) {
        // don't need incomplete type when accessing to_string using base pointer
    }

    MitmProxy* parent() { return parent_; }
    MitmProxy const* parent() const { return parent_; }
    void parent(MitmProxy* p) { parent_ = p; }

    std::unique_ptr<FilterResult>& result() { return result_; }

    TYPENAME_OVERRIDE("FilterProxy")
    DECLARE_LOGGING(to_string)

private:
    MitmProxy* parent_ {};
    std::unique_ptr<FilterResult> result_{};
};


#endif //FILTER_PROXY