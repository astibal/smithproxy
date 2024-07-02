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


#ifndef SMITHPROXY_PROFILES_HPP
#define SMITHPROXY_PROFILES_HPP

#include <policy/cfgelement.hpp>
#include <policy/addrobj.hpp>

class ProfileDetection : public socle::sobject, public CfgElement {

public:
    /*
     *  0   NONE
     *  1   POST -- works in all scenarios, but sometimes we can read data, which should
     *                   have been processed by upgraded com. Use PRE if possible.
     *  2   PRE  -- should be default, but not safe when cannot peek()
     */
    int mode = 0;
    bool engines_enabled = true;
    bool kb_enabled = true;

    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity) const override {
        return string_format("ProfileDetection: name=%s mode=%d", element_name().c_str(), mode);
    };

TYPENAME_OVERRIDE("ProfileDetection")
};

class ProfileContentRule : public socle::sobject, public CfgElement {

public:
    std::string match;
    std::string replace;
    bool fill_length = false;
    int replace_each_nth = 0;
    int replace_each_counter_ = 0;

    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity) const override {
        return string_format("ProfileContentRule: matching %s", ESC_(match).c_str());
    }

TYPENAME_OVERRIDE("ProfileContentRule")
};

struct ContentCaptureFormat {
    enum class write_format_type_t { SMCAP, PCAP_SINGLE, PCAP };
    using type_t = write_format_type_t;

    type_t value;

    using map_t = std::initializer_list<std::pair<type_t, const char*>>;
    static const inline map_t map_ = { { type_t::SMCAP, "smcap" },
                                       { type_t::PCAP, "pcap" },
                                       { type_t::PCAP_SINGLE, "pcap_single" }
                               };

    static const inline map_t extension_map_ = { { type_t::SMCAP, "smcap" },
                                       { type_t::PCAP, "pcapng" },
                                       { type_t::PCAP_SINGLE, "pcapng" }
    };

    ContentCaptureFormat() : value(type_t::SMCAP) {}
    ContentCaptureFormat(std::string const& v) : value(from_str(v)) {};
    ContentCaptureFormat(type_t v) : value(v) {};
    void operator=(std::string const& r) { value = from_str(r); }

    static std::string to_str(write_format_type_t t)  {
        std::string to_ret;
        for(auto const& r: map_) {
            if(r.first == t) {
                to_ret  = r.second;
                break;
            }
        }
        return to_ret;
    }

    static std::string to_ext(write_format_type_t t)  {
        std::string to_ret;
        for(auto const& r: extension_map_) {
            if(r.first == t) {
                to_ret  = r.second;
                break;
            }
        }
        return to_ret;
    }
    std::string to_ext() const { return to_ext(value); }

    static write_format_type_t from_str(std::string const& write_format) {
        type_t to_ret = write_format_type_t::SMCAP;

        for(auto const& r: map_) {
            if(r.second == write_format) {
                to_ret  = r.first;
                break;
            }
        }
        return to_ret;

    }

    std::string to_ext(std::string const& more_suf) const {
        auto suf = more_suf;
        suf.empty() ? suf += to_ext() : suf += "." + to_ext();
        return suf;
    }

    std::string to_str() const { return to_str(value); }
};

class ProfileContent  : public socle::sobject, public CfgElement {
public:
    // if true, content of proxy transmission will dumped to file
    bool write_payload = false;

    // content webhook options
    bool webhook_enable = false;
    bool webhook_lock_traffic = false;

    ContentCaptureFormat write_format;
    std::vector<ProfileContentRule> content_rules;

    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity) const override {
        std::string ret = string_format("ProfileContent: name=%s capture=%d", element_name().c_str(), write_payload);
        if(verbosity > INF) {
            for(auto const& it: content_rules)
                ret += string_format("\n        match: '%s'", ESC_(it.match).c_str());
        }

        return ret;
    };

TYPENAME_OVERRIDE("ProfileContent")
};


class FqdnAddress;
class CidrAddress;

class ProfileTls : public socle::sobject, public CfgElement  {
public:
    bool inspect = false;
    bool no_fallback_bypass = false;
    bool allow_untrusted_issuers = false;
    bool allow_invalid_certs = false;
    bool allow_self_signed = false;
    bool failed_certcheck_replacement = true;           //instead of resetting connection, spoof and display human-readable explanation why connection failed
    bool failed_certcheck_override = false;             //failed ssl replacement will contain option to temporarily allow the connection for the source IP.
    int  failed_certcheck_override_timeout = 600;       // if failed ssl override is active, this is the timeout.
    int  failed_certcheck_override_timeout_type = 0;    // 0 - just expire after the timeout
    // 1 - reset timeout on traffic (aka idle timer)

    bool mitm_cert_sni_search = true;                   // look in cache for certificates stored with SNI key
    bool mitm_cert_ip_search = true;                   // look in cache for certificates stored with IP key
    bool mitm_cert_searched_only = false;   // if SNI or IP cert is not found, don't use default spoofed mitm certificate

    bool use_pfs = true;         // general switch, more concrete take precedence
    bool left_use_pfs = true;
    bool right_use_pfs = true;
    bool left_disable_reuse = false;
    bool right_disable_reuse = false;

    int ocsp_mode = 0;           // 0 = disable OCSP checks ; 1 = check only end certificate ; 2 = check all certificates
    bool ocsp_stapling = false;
    int  ocsp_stapling_mode = 0; // 0 = loose, 1 = strict, 2 = require

    bool opt_ct_enable = true;
    bool opt_alpn_block = false;

    std::shared_ptr<std::vector<std::string>> sni_filter_bypass;
    std::shared_ptr<std::vector<FqdnAddress>> sni_filter_bypass_addrobj;
    socle::spointer_set_int redirect_warning_ports;

    bool sni_filter_use_dns_cache = true;       // if sni_filter_bypass is set, check during policy match if target IP isn't in DNS cache matching SNI filter entries.
    // For example:
    // Connection to 1.1.1.1 policy check will look in all SNI filter entries ["abc.com","mybank.com"] and will try to find them in DNS cache.
    // Sni filter entry mybank.com is found in DNS cache pointing to 1.1.1.1. Connection is bypassed.
    // Load increases with SNI filter length linearly, but DNS cache lookup is fast.
    // DNS cache has to be active this to be working.
    bool sni_filter_use_dns_domain_tree = true;
    // check IP address in full domain tree for each SNI filter entry.
    // if SNI filter entry can't be found in DNS cache, try to look in all DNS subdomains of SNI filter entries.
    // Example:
    // Consider SNI filter from previous example. You are now connecting to ip 2.2.2.2.
    // Based on previous DNS traffic, there is subdomain cache for "mybank.com" filled with entries "www" and "ecom".
    // Both "www" and "ecom" are searched in DNS cache. www points to 1.1.1.1, but ecom points to 2.2.2.2.
    // Connection is bypassed.
    // DNS cache has to active and sni_filter_use_dns_cache enabled before this feature can be activated.
    // Load increases with SNI filter size and subdomain cache, both linearly, so it's intensive feature.

    bool sslkeylog = false;                     // disable or enable ssl keylogging on this profile

    struct { ;
        bool suppress_all = false;
        bool suppress_common = true;
    } alerts {};

    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity) const override {
        std::string ret = string_format("ProfileTls: name=%s inspect=%d ocsp=%d ocsp_stap=%d pfs=%d,%d abr=%d,%d",
                                        element_name().c_str(),
                                        inspect,
                                        ocsp_mode, ocsp_stapling_mode,
                                        left_use_pfs, right_use_pfs,
                                        !left_disable_reuse, !right_disable_reuse);
        if(verbosity > INF) {

            ret += string_format("\n        disable fallback TLS bypass: %d", no_fallback_bypass);
            ret += string_format("\n        allow untrusted issuers: %d", allow_untrusted_issuers);
            ret += string_format("\n        allow invalid certs: %d", allow_invalid_certs);
            ret += string_format("\n        allow self-signed certs: %d", allow_self_signed);
            ret += string_format("\n        failed cert check html warnings: %d", failed_certcheck_replacement);
            ret += string_format("\n        failed cert check allow user override: %d", failed_certcheck_override);
            ret += string_format("\n        failed cert check user override timeout: %d", failed_certcheck_override_timeout);
            ret += string_format("\n        failed cert check user override timeout type: %d", failed_certcheck_override_timeout_type);
            ret += string_format("\n        look for SNI custom certificates: %d", mitm_cert_sni_search);
            ret += string_format("\n        look for IP custom certificates: %d", mitm_cert_ip_search);
            ret += string_format("\n        use _only_ custom certificates: %d", mitm_cert_searched_only);

            bool sni_out = false;
            if(sni_filter_bypass)
                for(auto const& it: *sni_filter_bypass) {
                    sni_out = true;
                    ret += string_format("\n        sni exclude: '%s'",ESC_(it).c_str());
                }

            if(sni_out) {
                ret += string_format("\n        sni exclude - use dns cache: %d",sni_filter_use_dns_cache);
                ret += string_format("\n        sni exclude - use dns domain tree: %d",sni_filter_use_dns_domain_tree);
                ret += "\n";
            }

            if(redirect_warning_ports.ptr())
                for(auto it: *redirect_warning_ports.ptr())
                    ret += string_format("\n        html warning port: '%d'",it);

        }

        return ret;
    }

TYPENAME_OVERRIDE("ProfileTls")
};

struct ProfileAuth;
struct ProfileAlgDns;
struct ProfileScript;
struct ProfileRouting;
class MitmProxy;

struct ProfileList {
    std::shared_ptr<ProfileContent> profile_content = nullptr;
    std::shared_ptr<ProfileDetection> profile_detection = nullptr;
    std::shared_ptr<ProfileTls> profile_tls = nullptr;
    std::shared_ptr<ProfileAuth> profile_auth = nullptr;
    std::shared_ptr<ProfileAlgDns> profile_alg_dns = nullptr;
    std::shared_ptr<ProfileScript> profile_script = nullptr;
    std::shared_ptr<ProfileRouting> profile_routing = nullptr;
};
struct ProfileSubAuth : public ProfileList, public CfgElement {
};

struct ProfileAuth : public CfgElement {
    bool authenticate = false;
    bool resolve = false;  // resolve traffic by ip in auth table
    std::vector<std::shared_ptr<ProfileSubAuth>> sub_policies;
};

struct ProfileAlgDns : public CfgElement {
    bool match_request_id = false;
    bool randomize_id = false;
    bool cached_responses = false;
};

struct ProfileScript : public CfgElement {
    std::string module_path;

    using script_t = enum { ST_PYTHON = 0, ST_GOLANG = 1};
    int script_type = -1;
};

struct ProfileRouting: public CfgElement {
    std::vector<std::string> dnat_addresses;
    std::vector<std::string> dnat_ports;

    using dnat_lb_method_t = enum class lb_method { LB_RR, LB_L3, LB_L4 };
    dnat_lb_method_t dnat_lb_method;

    // update internal state - run once per one request
    void update();

    // get (cached) address lookup candidates
    std::vector<std::shared_ptr<CidrAddress>> lb_candidates(int family) const;

    // helper to get index based on RR scheme
    size_t lb_index_rr(size_t sz) const;
    size_t lb_index_l3 (MitmProxy* proxy, size_t sz) const;
    size_t lb_index_l4(MitmProxy* proxy, size_t sz) const;

    struct LbState {
        constexpr static time_t refresh_interval = 5;

        std::mutex lock_;

        std::atomic_long rr_counter = 0;

        time_t last_refresh = 0;
        std::vector<std::shared_ptr<CidrAddress>> candidates_v4;
        std::vector<std::shared_ptr<CidrAddress>> candidates_v6;
        bool expand_candidates(std::vector<std::string> const& addresses);
    };

    LbState lb_state;
};


#endif //SMITHPROXY_PROFILES_HPP
