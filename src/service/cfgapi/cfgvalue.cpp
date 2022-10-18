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
#include <algorithm>
#include <libgen.h>

#include <ext/libcli/libcli.h>

#include <service/cfgapi/cfgvalue.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/cmd/cligen.hpp>
#include <common/log/logan.hpp>
#include <utils/str.hpp>


// @brief  - return true for numbers in the closed range
// @param template A integer range1
// @param template B interer range2
// @param v - string to check
// @note  template lambdas supported since C++20

CfgValue::filter_retval VALUE_UINT_RANGE_GEN(std::function<long long()> callableA, std::function<long long()> callableB, std::string const& v) {

    auto [ may_val, descr ] = CfgValue::VALUE_UINT(v);

    long long intA = callableA();
    long long intB = callableB();

    auto err = string_format("value must be a non-negative number in range <%ld,%ld>", intA, intB);

    long long port_value = safe_val(v);

    if(may_val.has_value() and port_value >= 0LL) {
        if(port_value < intA or port_value > intB)
            return CfgValue::filter_retval::reject(err);
        else
            return CfgValue::filter_retval::accept(may_val.value());
    }
    else {
        return CfgValue::filter_retval::reject(err);
    }

}

template <long long A, long long B>
CfgValue::filter_retval VALUE_UINT_RANGE(std::string const& v) {

    auto a = []() { return A; };
    auto b = []() { return B; };

    return VALUE_UINT_RANGE_GEN(a, b, v);
}



class is_in_vector {
public:
    using container_fetcher = std::vector<std::string>();

    is_in_vector(container_fetcher v, std::string n): get_the_container(std::function(v)), name(std::move(n)) {}
    is_in_vector(is_in_vector const& ref) : get_the_container(ref.get_the_container), name(ref.name) {}
    is_in_vector& operator=(is_in_vector const& ref) = default;


    CfgValue::filter_retval operator()(std::string const& v) {

        auto what = std::invoke(get_the_container);

        if(std::any_of(what.begin(), what.end(), [&v](auto const& k){ return k == v; }))
            return  CfgValue::filter_retval::accept(v);

        return CfgValue::filter_retval::reject(name);
    }
private:
    std::function<container_fetcher> get_the_container;
    std::string name;
};



void CfgValueHelp::init() {

    add("default", "")
    .help_quick("enter <value>");


    add("settings.certs_path", "directory for TLS-resigning CA certificate and key")
            .help_quick("<string>: (default: /etc/smithproxy/certs/default)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_DIR);

    add("settings.certs_ctlog", "file containing certificate transparency log list")
            .help_quick("<string>: file with certificate transparency keys (default: ct_log_list.cnf)")
            .value_filter(CfgValue::VALUE_FILE);

    add("settings.certs_ca_key_password", "TLS-resigning CA private key protection password")
            .help_quick("<string>: enter string value");

    add("settings.ca_bundle_path", "trusted CA store path (to verify server-side connections)")
            .help_quick("<string>: enter valid path")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_DIR);

    // listening ports

    add("settings.plaintext_port", "base divert port for non-SSL TCP traffic")
            .help_quick("<number>: a high port number")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024, 65535>);

    add("settings.ssl_port", "base divert port for SSL TCP traffic")
            .help_quick("<number>: a high port number")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024, 65535>);

    add("settings.udp_port", "base divert port for non-DTLS UDP traffic")
            .help_quick("<number>: a high port number")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024, 65535>);

    add("settings.dtls_port", "base divert port for DTLS UDP traffic")
            .help_quick("<number>: a high port number")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024, 65535>);

    add("settings.socks_port", "base SOCKS proxy listening port")
            .help_quick("<number>: a high port number")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024, 65535>);


    // worker setup

    add("settings.accept_tproxy", "whether to accept incoming connections via TPROXY")
            .help_quick("<bool>: set to 'true' to disable tproxy acceptor (default: false)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("settings.accept_redirect", "whether to accept incoming connections via REDIRECT")
            .help_quick("<bool>: set to 'true' to disable redirect acceptor (default: false)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("settings.accept_socks", "whether to accept incoming connections via SOCKS")
            .help_quick("<bool>: set to 'true' to disable socks acceptor (default: false)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    //


    auto VALUE_ZERO = []() -> int { return 0; };
    auto HW_THREADS = []() -> int { return static_cast<int>(std::thread::hardware_concurrency()); };
    auto HW_FILTER = [&] (std::string const& v) {
        return VALUE_UINT_RANGE_GEN(VALUE_ZERO, HW_THREADS, v);
    };

    add("settings.plaintext_workers", "non-SSL TCP traffic worker thread count")
            .help_quick("<number> acceptor subordinate worker threads count (max 4xCPU)")
            .may_be_empty(false)
            .value_filter(HW_FILTER);


    add("settings.ssl_workers", "SSL TCP traffic worker thread count")
            .help_quick("<number> acceptor subordinate worker threads count (max 4xCPU)")
            .may_be_empty(false)
            .value_filter(HW_FILTER);

    add("settings.udp_workers", "non-DTLS traffic worker thread count")
            .help_quick("<number> acceptor subordinate worker threads count (max 4xCPU)")
            .may_be_empty(false)
            .value_filter(HW_FILTER);


    add("settings.dtls_workers", "DTLS traffic worker thread count")
            .help_quick("<number> acceptor subordinate worker threads count (max 4xCPU)")
            .may_be_empty(false)
            .value_filter(HW_FILTER);

    add("settings.socks_workers", "SOCKS proxy traffic thread count")
            .help_quick("<number> acceptor subordinate worker threads count (max 4xCPU)")
            .may_be_empty(false)
            .value_filter(HW_FILTER);




    add("settings.ssl_autodetect", "Detect TLS ClientHello on unusual ports")
            .help_quick("<bool> set true to wait a short moment for TLS ClientHello on plaintext ports")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("settings.ssl_autodetect_harder", "Detect TSL ClientHello on unusual ports - wait a bit longer")
            .help_quick("<bool> set true to wait a bit longer for TLS ClientHello on plaintext ports")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);


    add("settings.ssl_ocsp_status_ttl", "obsoleted - hardcoded TTL for OCSP response validity")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_NONE);


    add("settings.ssl_crl_status_ttl", "obsoleted - hardcoded TTL for downloaded CRL files")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_NONE);


    add("settings.log_level", "default file logging verbosity level")
            .help_quick("<number> between 0 and 8 to highest verbosity. Debug level is set by topics in CLI")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<0,8>);

    add("settings.log_file", "log file")
            .help_quick("<filename template> file for logging. Must include '^s' for tenant name expansion.")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BASEDIR)
            .value_filter([](std::string const& v) -> CfgValue::filter_retval {

                std::string orig = v;
                std::string base = v;
                base = ::basename((char*)v.c_str());

                auto where = base.find("^s");
                if(where == v.npos) {

                    return CfgValue::filter_retval::reject("filename must contain '^s' for tenant name expansion.");
                }

                sx::str::string_replace_all(orig, "^s", "%s");
                return CfgValue::filter_retval::accept(orig);
            });

    add("settings.log_console", "toggle logging to standard output")
        .may_be_empty(false)
        .value_filter(CfgValue::VALUE_BOOL);


    add("settings.syslog_server", "IP address of syslog server")
        .value_filter(CfgValue::VALUE_IPHOST);

    add("settings.syslog_port", "syslog server port")
        .value_filter(VALUE_UINT_RANGE<0,65535>);

    add("settings.syslog_facility", "syslog facility")
        .help_quick("syslog facility (default 23 = local7)")
        .value_filter(VALUE_UINT_RANGE<0,32>);




    add("settings.syslog_level", "syslog logging verbosity level")
        .help_quick("syslog level (default 6 = informational)")
        .value_filter(VALUE_UINT_RANGE<0,8>);



    add("settings.syslog_family", "IPv4 or IPv6?")
        .help_quick("set to 4 or 6 for ip version")
        .value_filter([](std::string const& v) -> CfgValue::filter_retval {
            if(v == "4" or v == "6") {
                return CfgValue::filter_retval::accept(v);
            }
            return CfgValue::filter_retval::reject("must be empty to set default, 4, or 6.");
        });

    add("settings.sslkeylog_file", "where to dump TLS keying material")
        .help_quick("file path where to dump tls keys (if set)")
        .value_filter(CfgValue::VALUE_BASEDIR);

    add("settings.messages_dir", "replacement text directory")
        .help_quick("directory path to message files")
        .may_be_empty(false)
        .value_filter(CfgValue::VALUE_DIR);

    add("settings.write_payload_dir", "root directory for packet dumps")
        .help_quick("directory path for payload dump files")
        .may_be_empty(false)
        .value_filter(CfgValue::VALUE_DIR);

    add("settings.write_payload_file_prefix", "packet dumps file context")
        .help_quick("dump filename context");

    add("settings.write_payload_file_suffix", "packet dumps file suffix")
        .help_quick("dump filename suffix");

    add("settings.write_pcap_single_quota", "on how many bytes roll over pcap_single file (0 means never)")
            .help_quick("<number>")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<0LL, LLONG_MAX>); //10M

    // sections
    add("settings.auth_portal", "** configure authentication portal settings");
    add("settings.auth_portal.address", "IP of FQDN where user is redirected for authentication")
    .may_be_empty(false);
    add("settings.auth_portal.http_port", "port where user is redirected for HTTP authentication")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024,65535>);
    add("settings.auth_portal.https_port", "port where user is redirected for HTTPS authentication")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024,65535>);
    add("settings.auth_portal.ssl_key", "key for HTTPS authentication certificate")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_FILE);
    add("settings.auth_portal.ssl_cert", "HTTPS authentication certificate file")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_FILE);
    add("settings.auth_portal.magic_ip", "Rendezvous IP for client traffic")
            .may_be_empty(false)
            .value_filter([](auto const&v){
                auto ip = CidrAddress(v);
                if(ip.cidr()) {
                    if(std::string(cidr_numhost(ip.cidr())) == "1") {
                        return CfgValue::filter_retval::accept(v);
                    }
                }
                return CfgValue::filter_retval::reject("must me a valid host IP address");
            });


    add("settings.tuning", "** tune selected internals");
    add("settings.tuning.proxy_thread_spray_min", "minimum worker sub-proxies for activating thread spraying")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<0,65535>);
    add("settings.tuning.host_bufsz_min", "initial io buffer size")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1500,10000000>);
    add("settings.tuning.host_bufsz_max_multiplier", "multiplier of min to get maximal buffer size")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1,1024000000>);
    add("settings.tuning.host_write_full", "unwritten remote bytes threshold to slower reads")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<1024,1024000000>);



    add("settings.cli", "** configure CLI specific settings");
    add("settings.cli.port", "base port where CLI is listening for telnet connections")
        .may_be_empty(false)
        .value_filter(VALUE_UINT_RANGE<1024, 65535>);

    add("settings.cli.enable_password", "enable password");


    add("settings.socks", "** configure SOCKS specific settings");
    add("settings.socks.async_dns", "run DNS requests asynchronously")
        .may_be_empty(false)
        .value_filter(CfgValue::VALUE_BOOL);


    add("settings.accept_api", "whether to accept HTTP API request")
            .help_quick("<bool>: set to 'true' to disable API server (default: true)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("settings.http_api", "API access options");
    add("settings.http_api.keys", "API access keys to retrieve API access tokens");
    add("settings.http_api.key_timeout", "Expiration timeout for session tokens")
            .help_quick("<positive integer>: ttl in seconds")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_UINT_NZ);

    add("settings.http_api.port", "TCP port for API HTTPS access")
            .help_quick("<number>: port number (default: 55555)")
            .value_filter(VALUE_UINT_RANGE<1024,65535>);

#ifdef USE_PAM
    add("settings.http_api.pam_login", "enable API login using system account")
            .help_quick("<bool>: set to false to disable API login via PAM")
#else
    add("settings.http_api.pam_login", "(NOT USABLE) enable API login using system account")
            .help_quick("<bool>: (NOT USABLE) set to false to disable API login via PAM")
#endif
            .may_be_empty(false)
            .help_quick("<bool>: set to false to disable API login via PAM")
            .value_filter(CfgValue::VALUE_BOOL);


    add("settings.admin", "administration options");
    add("settings.admin.group", "system group with granted access; empty means root.")
            .help_quick("<string>: existing group name")
            .may_be_empty(true);

    add("settings.http_api.key_extend_on_access", "If set, tokens are refreshed when used")
            .help_quick("<bool>: set true to refresh tokens when used (default: true)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("settings.http_api.loopback_only", "Listen to loopback only (default)")
            .help_quick("<bool>: set true to listen only on loopback address (default: true)")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);


    add("debug.log_data_crc", "calculate received CRC data (helps to identify proxy bugs)");

    add("proto_objects", "IP protocols")
        .help_quick("list of protocol objects");

    add("proto_objects.[x].id", "IP protocol number (tcp=6, udp=17)")
        .help_quick("<number> protocol id (1-255)")
        .may_be_empty(false)
        .value_filter(VALUE_UINT_RANGE<1,255>);


    add("port_objects", "TCP/UDP ports");
    add("port_objects.[x].start", "port range start")
        .may_be_empty(false)
        .value_filter(VALUE_UINT_RANGE<0,65535>);
    add("port_objects.[x].end", "port range end")
        .may_be_empty(false)
        .value_filter(VALUE_UINT_RANGE<0,65535>);

    add("policy.[x].proto", "protocol to match (see proto_objects)")
        .may_be_empty(false)
        .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_proto(); },"must be in proto_objects"))
        .suggestion_generator([](std::string const& section, std::string const& variable) {
            return CfgFactory::get()->keys_of_db_proto();
        });

    add("policy.[x].src", "source address to match")
        .may_be_empty(true)
        .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_address(); },"must be in address_objects"))
        .suggestion_generator([](std::string const& section, std::string const& variable) {
            return CfgFactory::get()->keys_of_db_address();
        });
    add("policy.[x].dst", "destination address to match")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_address(); },"must be in address_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                return CfgFactory::get()->keys_of_db_address();
            });

    add("policy.[x].dport", "destination port to match")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_port(); },"must be in port_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                return CfgFactory::get()->keys_of_db_port();
            });

    add("policy.[x].sport", "source port to match")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_port(); },"must be in port_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                return CfgFactory::get()->keys_of_db_port();
            });

    add("policy.[x].action", "action to take with matching traffic")
            .may_be_empty(false)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return {"accept", "reject"}; },"accept, or reject"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return {"accept", "reject"}; ;
            });

    add("policy.[x].nat", "nat options")
            .may_be_empty(false)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return {"auto", "none"}; },"auto, or none"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return {"auto", "none"};;
            });

    add("policy.[x].tls_profile", "tls options")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_prof_tls(); },"must be in tls_profiles"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_prof_tls();
            });

    add("policy.[x].detection_profile", "detection options")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_prof_detection(); },"must be in detection_profiles"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_prof_detection();
            });

    add("policy.[x].content_profile", "content options")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_prof_content(); },"must be in content_profiles"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_prof_content();
            });

    add("policy.[x].auth_profile", "auth options")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_prof_auth(); },"must be in auth_profiles"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_prof_auth();
            });

    add("policy.[x].alg_dns_profile", "alg_dns_profile options")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_prof_alg_dns(); },"must be in alg_dns_profile"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_prof_alg_dns();
            });

    add("policy.[x].routing", "routing")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return CfgFactory::get()->keys_of_db_routing_or_none(); },"must be in routing, or 'none'"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {
                return CfgFactory::get()->keys_of_db_routing_or_none();
            });


    add("content_profiles.[x].write_format", "smcap, pcap, pcap_single")
            .help_quick("<string>: smcap, pcap, pcap_single")
            .may_be_empty(false)
            .value_filter(is_in_vector([]() -> std::vector<std::string> { return {"smcap", "pcap", "pcap_single"}; },"smcap, pcap or pcap_single"))
            .suggestion_generator([](std::string const& section, std::string const& variable) -> std::vector<std::string> {  return {"smcap", "pcap", "pcap_single"};   });


    add("detection_profiles.[x].mode", "0 = disabled, 1 = enabled")
            .help_quick("<integer>: 0-1")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<0,1>);


    add("detection_profiles.[x].engines_enabled", "enable/disable L7 engines")
            .help_quick(CfgValue::HELP_BOOL)
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL)
            .suggestion_generator(CfgValue::SUGGESTION_BOOL);

    add("detection_profiles.[x].kb_enabled", "enable/disable knowledge base information collection")
            .help_quick(CfgValue::HELP_BOOL)
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL)
            .suggestion_generator(CfgValue::SUGGESTION_BOOL);


    init_routing();
    init_captures();

    #ifdef USE_EXPERIMENT
    init_experiment();
    #endif
}


void CfgValueHelp::init_routing() {
    add("routing.[x].dnat_address", "change destination address")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_address(); },"must be in address_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                return CfgFactory::get()->keys_of_db_address();
            });

    add("routing.[x].dnat_port", "change destination port ")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { return CfgFactory::get()->keys_of_db_port(); },"must be in port_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                return CfgFactory::get()->keys_of_db_port();
            });
    add("routing.[x].dnat_lb_method", "how to distribute connections if more targets")
            .may_be_empty(true)
            .value_filter(is_in_vector([]() { std::vector<std::string> r {"round-robin", "sticky-l3", "sticky-l4" }; return r; }, "must be in port_objects"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                std::vector<std::string> r {"round-robin", "sticky-l3", "sticky-l4" }; return r;
            });
}

void CfgValueHelp::init_captures () {
    add("captures.local.enabled", "globally enable/disable file captures")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL)
            .suggestion_generator(CfgValue::SUGGESTION_BOOL);

    add("captures.local.pcap_quota", "Max size of pcap_single file (in MB). Zero means no limits.")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_UINT);

    add("captures.local.dir", "directory where to write capture files")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_DIR);

    add("captures.local.format", "capture file format")
            .may_be_empty(false)
            .value_filter(is_in_vector([]() { std::vector<std::string> r {"pcap_single", "pcap", "smcap" }; return r; },
                                       "write into single pcap, per-connection pcap, or per connection smcap"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                std::vector<std::string> r {"pcap_single", "pcap", "smcap" }; return r;
            });

    add("captures.remote.enabled", "globally enable/disable tunnelled capture emission")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL);

    add("captures.remote.tun_type", "select tunnelling protocol")
            .may_be_empty(false)
            .value_filter(is_in_vector([]() { std::vector<std::string> r {"gre", }; return r; },
                                       "tunnel type"))
            .suggestion_generator([](std::string const& section, std::string const& variable) {
                std::vector<std::string> r{"gre",};
                return r;
            });

    add("captures.remote.tun_dst", "set tunnel destination IP address")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_IPHOST);
    add("captures.remote.tun_ttl", "set tunnel TTL (ie. to not accidentally leave your premises)")
            .may_be_empty(false)
            .value_filter(VALUE_UINT_RANGE<0,255>);



}

#ifdef USE_EXPERIMENT
void CfgValueHelp::init_experiment() {
    add("experiment.enabled_1", "enable/disable experiment #1")
            .may_be_empty(false)
            .value_filter(CfgValue::VALUE_BOOL)
            .suggestion_generator(CfgValue::SUGGESTION_BOOL);

    add("experiment.param_1", "set parameter for experiment #1")
            .may_be_empty(true)
            .value_filter(CfgValue::VALUE_ANY);
}
#endif

std::pair<std::optional<std::string>, std::string> CfgValueHelp::value_check(std::string const& varname, std::string const& value_argument) {

    auto masked_varname = sx::str::cli::mask_array_index(varname);

    auto cli_e = find(masked_varname);
    bool may_be_empty = true;

    struct filter_result_e {
        filter_result_e(bool b, std::string const& v) : value_filter_check(b), value_filter_check_response(v) {};
        bool value_filter_check = true;
        std::string value_filter_check_response;
    };
    std::list<filter_result_e> filter_result;
    auto value_modified = value_argument;


    if(not cli_e.has_value()) {
        // try also mask the parent
        auto masked_parent = sx::str::cli::mask_parent(varname);
        cli_e = find(masked_parent);
    }


    if(cli_e.has_value()) {
        may_be_empty = cli_e->get().may_be_empty();

        if(not value_modified.empty()) {

            unsigned int i = 0;
            for(auto this_filter: cli_e->get().value_filter()) {
                auto retval = std::invoke(this_filter, value_modified);

                // value is not applicable according to this filter
                if(not retval.accepted()) {

                    filter_result.emplace_back(false, retval.get_comment());

                    break;
                } else {
                    value_modified = retval.get_value();
                    filter_result.emplace_back(true, retval.get_comment());

                    i++;
                }
            }
        }
    }


    // empty value check
    if(value_argument.empty() and not may_be_empty) {

        return { std::nullopt, "this attribute cannot be empty" };
    }


    for(auto const& fr: filter_result) {
        if(not fr.value_filter_check) {
            return { std::nullopt, string_format("Value check failed: %s", fr.value_filter_check_response.c_str()) };
        }
    }



    auto path_elems = string_split(masked_varname, '.');
    try {
        if (masked_varname.find("policy.[x]") == 0) {

            // check policy
            if(path_elems[2] == "src" or path_elems[2] == "dst") {

                auto addrlist = CfgFactory::get()->keys_of_db_address();
                if(std::find(addrlist.begin(), addrlist.end(), value_modified) == addrlist.end()) {
                    return { std::nullopt, string_format("policy values for %s: %s not found address db", path_elems[2].c_str(), value_modified.c_str()) };
                }
            }
        }
    }
    catch(std::out_of_range const& e) {
        return { std::nullopt, "value_check: returning FAILED: out of range" };
    }

    return { value_modified, "" };
}


std::string CfgValueHelp::help(help_type_t htype, const std::string& section, const std::string& key) {

    std::regex match ("\\[[0-9]+\\]");
    std::string masked_section  = std::regex_replace (section, match, "[x]");

    auto what = masked_section + "." + key;
    auto cli_e = find(what);

    if(not cli_e.has_value()) {
        std::regex remove_last_part("\\.[^.]+$");
        masked_section = std::regex_replace(section, remove_last_part, ".[x]");
        cli_e = find(masked_section + "." + key);
    }


    if(cli_e.has_value()) {
        if (htype == CfgValueHelp::help_type_t::HELP_QMARK) {
            return cli_e->get().help_quick();
        } else {
            return cli_e->get().help();
        }
    }

    return std::string();
}