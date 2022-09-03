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

#ifndef MITMHOSTCX_HPP
 #define MITMHOSTCX_HPP

#include <inspect/engine.hpp>
#include <apphostcx.hpp>
#include <policy/inspectors.hpp>

class MitmHostCX final : public AppHostCX, public socle::sobject {
public:
    ~MitmHostCX() override = default;
    
    MitmHostCX(baseCom* c, const char* h, const char* p );
    MitmHostCX( baseCom* c, int s );

    std::size_t process_in() override;
    std::size_t process_out() override;
    void load_signatures();

    
    std::vector<std::unique_ptr<Inspector>> inspectors_;
    void inspect(char side) override;
    void on_detect(std::shared_ptr<duplexFlowMatch> x_sig, flowMatchState& s, vector_range& r) override;

    sx::engine::EngineCtx engine_ctx;
    void engine_run(std::string const& name, sx::engine::EngineCtx &e) const;

    void on_starttls() override;

    int matched_policy() const { return matched_policy_; }
    void matched_policy(int p) { matched_policy_ = p; }

    using replacetype_t = enum { REPLACETYPE_NONE=0, REPLACETYPE_HTTP=1 };
    replacetype_t replacement_type() const { return replacement_type_; }
    void replacement_type(replacetype_t r) { replacement_type_ = r; }
    
    using replaceflags_t = enum { REPLACE_NONE=0, REPLACE_REDIRECT=1, REPLACE_BLOCK=2 };
    void replacement_flag(replaceflags_t i) { replacement_flags_ = i; }
    replaceflags_t replacement_flag()   { return replacement_flags_; }
    
    int inspection_verdict() const { return inspect_verdict; };
    std::shared_ptr<buffer> inspection_verdict_response() const { return  inspect_verdict_response; }

    bool opt_engines_enabled = true;
    bool opt_kb_enabled = true;

    bool is_ssl = false;
    bool is_ssl_port = false;
    
    bool is_http = false;
    bool is_http_port = false;

    bool is_dns = false;
    bool is_dns_port = false;

    bool ask_destroy() override;
    std::string to_string(int verbosity) const override;
    auto const& get_log() const { return log; }
    
private:
    int matched_policy_ = -1;

    replacetype_t replacement_type_ = REPLACETYPE_NONE;
    replaceflags_t replacement_flags_ = REPLACE_NONE;

    unsigned int inspect_cur_flow_size = 0;
    unsigned int inspect_flow_same_bytes = 0;
    int inspect_verdict = Inspector::OK;
    std::shared_ptr<buffer> inspect_verdict_response;

public:
    TYPENAME_OVERRIDE("MitmHostCX")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"com.proxy"};

};

#endif