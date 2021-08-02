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

#ifndef DNSINSPECTOR_HPP
#define DNSINSPECTOR_HPP

#include <policy/inspectors.hpp>

class DNS_Inspector : public Inspector {
public:
    explicit DNS_Inspector() {
        log = logan::attach(this, "dns");
    }
    ~DNS_Inspector() override = default;

    void update(AppHostCX* cx) override;

    bool l4_prefilter(AppHostCX* cx) override { return interested(cx); };
    bool interested(AppHostCX*cx) const override ;

    static bool dns_prefilter(AppHostCX* cx);

    bool opt_match_id = false;
    bool opt_randomize_id = false;
    bool opt_cached_responses = false;

    std::shared_ptr<DNS_Request> find_request(uint16_t r) { auto it = requests_.find(r); if(it == requests_.end()) { return nullptr; } else { return it->second; }  }
    bool validate_response(std::shared_ptr<DNS_Response> ptr);
    bool store(std::shared_ptr<DNS_Response> ptr);
    void apply_verdict(AppHostCX* cx) override;

    std::string to_string(int verbosity) const override;

    std::shared_ptr<buffer> verdict_response() override { return cached_response; };
private:
    logan_attached<DNS_Inspector> log;
    bool is_tcp = false;

    std::shared_ptr<buffer> cached_response = nullptr;
    uint16_t cached_response_id = 0;
    std::vector<unsigned int> cached_response_ttl_idx;
    uint32_t cached_response_decrement = 0;

    std::unordered_map<uint16_t,std::shared_ptr<DNS_Request>>  requests_;
    int responses_ = 0;
    bool stored_ = false;

    TYPENAME_OVERRIDE("DNS_Inspector")
    DECLARE_LOGGING(to_string)
};



#endif //DNSINSPECTOR_HPP
