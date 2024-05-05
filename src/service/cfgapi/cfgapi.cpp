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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <vector>

#include <socle.hpp>
#include <main.hpp>


#include <service/cfgapi/cfgapi.hpp>
#include <service/cmd/clistate.hpp>
#include <log/logger.hpp>

#include <policy/policy.hpp>
#include <policy/authfactory.hpp>
#include <inspect/sigfactory.hpp>
#include <inspect/sxsignature.hpp>

#include <proxy/mitmproxy.hpp>
#include <proxy/mitmhost.hpp>

#include <proxy/filters/sinkhole.hpp>
#include <proxy/filters/statsfilter.hpp>
#include <proxy/filters/access_filter.hpp>

#include <inspect/dnsinspector.hpp>
#include <inspect/pyinspector.hpp>

#include <service/httpd/httpd.hpp>
#include <service/http/webhooks.hpp>

using namespace libconfig;

std::map<std::string, std::shared_ptr<CfgElement>>& CfgFactory::section_db(std::string const& section) {
    if(section == "proto_objects" or section == "proto_objects.[x]") {
        return db_proto;
    }
    else if(section == "port_objects" or section == "port_objects.[x]") {
        return db_port;
    }
    else if(section == "address_objects" or section == "address_objects.[x]") {
        return db_address;
    }
    else if(section == "detection_profiles" or section == "detection_profiles.[x]") {
        return db_prof_detection;
    }
    else if(section == "content_profiles"  or section == "content_profiles.[x]") {
        return db_prof_content;
    }
    else if(section == "tls_ca" or section == "tls_ca.[x]") {
        return db_prof_tls_ca;
    }
    else if(section == "tls_profiles" or section == "tls_profiles.[x]") {
        return db_prof_tls;
    }
    else if(section == "alg_dns_profiles" or section == "alg_dns_profiles.[x]") {
        return db_prof_alg_dns;
    }
    else if(section == "auth_profiles" or section == "auth_profiles.[x]") {
        return db_prof_auth;
    }
    else if(section == "routing" or section == "routing.[x]") {
        return db_routing;
    }
    else if(section == "policy" or section == "address_objects.[x]") {
        return db_policy;
    }

    auto msg = string_format("no such db section %s", section.c_str());
    throw std::invalid_argument(msg.c_str());
}

bool CfgFactory::cfgapi_init(const char* fnm) {
    
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    _dia("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfgapi.readFile(fnm);
    }
    catch(const FileIOException &fioex)
    {
        _err("I/O error while reading config file: %s: %s", fnm, fioex.what());
        return false;   
    }
    catch(const ParseException &pex)
    {
        _err("Parse error in %s at %s:%d - %s", fnm, pex.getFile(), pex.getLine(), pex.getError());
        return false;
    }
    
    return true;
}

std::shared_ptr<CfgAddress> CfgFactory::lookup_address (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_address.find(name) != db_address.end()) {
        return std::dynamic_pointer_cast<CfgAddress>(db_address[name]);
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<CidrAddress>>
CfgFactory::expand_to_cidr (std::vector<std::string> const& address_names, int cidr_flags) {
    // lock cfg, don't lock anything else

    std::vector<std::shared_ptr<CidrAddress>> to_ret;

    auto cfglock = std::scoped_lock(lock_);

    // for each dnat address find CidrAddress
    for(auto const& n: address_names) {
        auto obj = lookup_address(n.c_str());

        if(not obj) continue;

        // dig out AddressObject

        if(auto cidr = std::dynamic_pointer_cast<CidrAddress>(obj->value()); cidr) {

            if(cidr_flags == CIDR_IPV4 and cidr->cidr()->proto != CIDR_IPV4) continue;
            if(cidr_flags == CIDR_IPV6 and cidr->cidr()->proto != CIDR_IPV6) continue;

            to_ret.push_back(cidr);
        }
        else if(auto fq = std::dynamic_pointer_cast<FqdnAddress>(obj->value()); fq) {

            auto find_dns_entries = [&](auto IPV) {
                std::shared_ptr<DNS_Response> dns = fq->find_dns_response(IPV);
                if(not dns) return;

                auto ips = dns->get_a_anwsers();

                for (auto const &ip: ips) {
                    auto ip_val = ip->ip(CIDR_ONLYADDR);

                    // make new CidrAddress
                    to_ret.emplace_back(std::make_shared<CidrAddress>(ip_val));
                }
            };

            if(cidr_flags != CIDR_IPV6) find_dns_entries(CIDR_IPV4);
            if(cidr_flags != CIDR_IPV4) find_dns_entries(CIDR_IPV6);
        }
    }

    return to_ret;
}


std::shared_ptr<CfgRange> CfgFactory::lookup_port (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_port.find(name) != db_port.end()) {
        return std::dynamic_pointer_cast<CfgRange>(db_port[name]);
    }    
    
    return std::make_shared<CfgRange>(NULLRANGE);
}

std::shared_ptr<CfgString> CfgFactory::lookup_features (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(db_features.find(name) != db_features.end()) {
        return std::dynamic_pointer_cast<CfgString>(db_features[name]);
    }

    return nullptr;
}

std::shared_ptr<CfgUint8> CfgFactory::lookup_proto (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_proto.find(name) != db_proto.end()) {
        return std::dynamic_pointer_cast<CfgUint8>(db_proto[name]);
    }    
    
    return std::make_shared<CfgUint8>(0);
}

std::shared_ptr<ProfileContent> CfgFactory::lookup_prof_content (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_prof_content.find(name) != db_prof_content.end()) {
        return std::dynamic_pointer_cast<ProfileContent>(db_prof_content[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileDetection> CfgFactory::lookup_prof_detection (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_prof_detection.find(name) != db_prof_detection.end()) {
        return std::dynamic_pointer_cast<ProfileDetection>(db_prof_detection[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileTls> CfgFactory::lookup_prof_tls (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_prof_tls.find(name) != db_prof_tls.end()) {
        return std::dynamic_pointer_cast<ProfileTls>(db_prof_tls[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileAlgDns> CfgFactory::lookup_prof_alg_dns (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_prof_alg_dns.find(name) != db_prof_alg_dns.end()) {
        return std::dynamic_pointer_cast<ProfileAlgDns>(db_prof_alg_dns[name]);
    }    
    
    return nullptr;

}

std::shared_ptr<ProfileScript> CfgFactory::lookup_prof_script(const char * name)  {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(db_prof_script.find(name) != db_prof_script.end()) {
        return std::dynamic_pointer_cast<ProfileScript>(db_prof_script[name]);
    }

    return nullptr;

}

std::shared_ptr<ProfileAuth> CfgFactory::lookup_prof_auth (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(db_prof_auth.find(name) != db_prof_auth.end()) {
        return std::dynamic_pointer_cast<ProfileAuth>(db_prof_auth[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileRouting> CfgFactory::lookup_prof_routing(const char * name)  {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(db_routing.find(name) != db_routing.end()) {
        return std::dynamic_pointer_cast<ProfileRouting>(db_routing[name]);
    }

    return nullptr;

}


std::optional<int> version_compare(std::string const& v1, std::string const& v2) {
    auto vers1 = string_split(v1, '.');
    auto vers2 = string_split(v2, '.');

    if(vers1.size() != vers2.size()) return std::nullopt;

    int result;

    int index = 0;
    for(auto const& cur1: vers1) {

        auto i1 = safe_val(cur1);
        auto i2 = safe_val(vers2[index]);

        if(i1 < 0 or i2 < 0) return std::nullopt;

        result = i2 - i1;
        if(result != 0)
            break;

        index++;
    }

    return result;
}

// upgrade from previous schema number
// Any action here is applied to active configuration - which is later saved
// if returned true.

bool CfgFactory::upgrade_schema(int upgrade_to_num) {

    // save 'captures' new section and removes settings
    if(upgrade_to_num == 1001) return true;

    // added elements in captures.remote
    else if(upgrade_to_num == 1002) {
        CfgFactory::get()->capture_remote.enabled = false;
        return true;
    }
    // file suffix is added automatically, reset if not set to something custom
    else if(upgrade_to_num == 1003) {
        auto s = CfgFactory::get()->capture_local.file_suffix;
        if(s == "pcapng" or s == "pcap" or s == "smcap") {
            CfgFactory::get()->capture_local.file_suffix = "";
        }
        return true;
    }
    else if(upgrade_to_num == 1004) {
        // save setting.tuning group
        return true;
    }
    else if(upgrade_to_num == 1005) {
        // save setting.socks group, new ipv6-related options
        return true;
    }
    else if(upgrade_to_num == 1006) {
        log.event(INF, "added detection_profile.[x].engine_enabled");
        log.event(INF, "added detection_profile.[x].kb_enabled");
        return true;
    }
    else if(upgrade_to_num == 1007) {
        log.event(INF, "added settings.http_api section");
        log.event(INF, "added settings.http_api section.keys array");

        unsigned char rand_pool[16];
        RAND_bytes(rand_pool, 16);

        if(sx::webserver::HttpSessions::api_keys.empty()) {

            auto lc_ = std::scoped_lock(sx::webserver::HttpSessions::lock);
            sx::webserver::HttpSessions::api_keys.emplace(hex_print(rand_pool, 16));
            log.event(INF, "new API key generated");
        }

        return true;
    }
    else if(upgrade_to_num == 1008) {
        log.event(INF, "added settings.http_api.key_timeout");
        log.event(INF, "added settings.http_api.key_extend_on_access");

        return true;
    }
    else if(upgrade_to_num == 1009) {
        log.event(INF, "added settings.http_api.loopback_only");

        return true;
    }
    else if(upgrade_to_num == 1010) {
        log.event(INF, "added settings.admin section");
        log.event(INF, "added settings.admin.group string variable");

        return true;
    }
    else if(upgrade_to_num == 1011) {
        log.event(INF, "added settings.http_api.pam_login");
        log.event(INF, "added settings.http_api.port");

        return true;
    }
    else if(upgrade_to_num == 1012) {
        log.event(INF, "address_objects changes");

        return true;
    }
    else if(upgrade_to_num == 1013) {
        log.event(INF, "added settings.certs_ca_file");
        return true;
    }
    else if(upgrade_to_num == 1014) {
        log.event(INF, "added tls_profiles.[x].sni_based_cert");
        return true;
    }
    else if(upgrade_to_num == 1015) {
        log.event(INF, "added tls_profiles.[x].ip_based_cert");
        return true;
    }
    else if(upgrade_to_num == 1016) {
        log.event(INF, "added policy.[x].features");
        return true;
    }
    else if(upgrade_to_num == 1017) {
        log.event(INF, "added settings.webhook");
        log.event(INF, "added settings.webhook.enabled");
        log.event(INF, "added settings.webhook.url");
        log.event(INF, "added settings.webhook.tls_verify");
        return true;
    }
    else if(upgrade_to_num == 1018) {
        log.event(INF, "added settings.webhook.hostid");
        return true;
    }
    else if(upgrade_to_num == 1019) {
        log.event(INF, "added captures.options section");
        log.event(INF, "added captures.options.calculate_checksums");
        return true;
    }
    else if(upgrade_to_num == 1020) {
        log.event(INF, "added policy feature 'access-request'");
        return true;
    }
    else if(upgrade_to_num == 1021) {
        log.event(INF, "added settings.tuning.subproxy_thread_spray_bytes_min");
        log.event(INF, "default settings.tuning.subproxy_thread_spray_min changed 2->5");
        return true;
    }
    else if(upgrade_to_num == 1022) {
        log.event(INF, "added tls_profiles.[x].only_custom_certs");
        return true;
    }
    else if(upgrade_to_num == 1023) {
        log.event(INF, "added tls_profiles.[x].no_fallback_bypass");
        return true;
    }
    else if(upgrade_to_num == 1024) {
        log.event(INF, "added content_profiles.[x].webhook_enable");
        log.event(INF, "added content_profiles.[x].webhook_lock_traffic");
        return true;
    }
    else if(upgrade_to_num == 1025) {
        log.event(INF, "added settings.webhook.api_override");
        return true;
    }
    else if(upgrade_to_num == 1026) {
        log.event(INF, "added settings.http_api.bind_address");
        log.event(INF, "added settings.http_api.bind_interface");
        log.event(INF, "added settings.http_api.allowed_ips");
        return true;
    }
    else if(upgrade_to_num == 1027) {
        log.event(INF, "added settings.webhook.bind_interface");
        return true;
    }

    return false;
}

bool CfgFactory::upgrade_by_version(std::string const& from) {

    std::cout << "upgrade check: " << from << " -> " << SMITH_VERSION  << std::endl;

    if(version_compare(SMITH_VERSION, "0.9.23").value_or(-1) > 0) {
        return upgrade_to_0_9_23();
    }

    // Don't use version-based upgrade, unless it's unrelated to configuration file
    // and needs specific care.

    // Version-based upgrade is deprecated - use schema numbering
    // which is decoupled from versions.

    return false;
}

bool CfgFactory::upgrade_to_0_9_23 () {

    std::cout << "upgrade script to 0.9.23" << std::endl;

    if(long long tmp; load_if_exists(CfgFactory::cfg_root()["settings"], "write_pcap_single_quota", tmp)) {
        traflog::PcapLog::single_instance().stat_bytes_quota = tmp / (1024 * 1024);
    }
    return true;
}

bool CfgFactory::upgrade_and_save() {


    auto backup = [this](std::string const& prev_ver) {
        try {
            std::stringstream ss;
            ss << CfgFactory::get()->config_file;
            ss << "." << prev_ver << ".bak.cfg";

            #if ( LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7 )
            cfgapi.setOptions(Setting::OptionOpenBraceOnSeparateLine);
            #else
            cfgapi.setOptions(Config::OptionOpenBraceOnSeparateLine);
            #endif

            cfgapi.setTabWidth(4);
            cfgapi.writeFile(ss.str().c_str());
        }
        catch(ConfigException const& e) {
            _err("error writing config file backup %s", e.what());
            return false;
        }

        return true;
    };

    auto save_status = [this]() -> bool {
        if(not save_config()) {
            _err("cannot upgrade_version config file");
            return false;
        }
        return true;
    };

    bool do_save = false;


#if ( not defined USE_EXPERIMENT and defined BUILD_RELEASE )

    //remove experiment (and save config) when running non-experimental release build

    if(cfgapi.getRoot().exists("experiment")) {
        cfgapi.getRoot().remove("experiment");
        do_save = true;
    }
#elif defined USE_EXPERIMENT

    if(not cfgapi.getRoot().exists("experiment")) {
        auto& ex = cfgapi.getRoot().add("experiment", Setting::TypeGroup);
        ex.add("enabled_1", libconfig::Setting::TypeBoolean) = false;
        ex.add("param_1", libconfig::Setting::TypeString) = "";
        do_save = true;
    }

#endif


    if(not cfgapi.getRoot().exists("*_internal_*")) {

        // versioning first initialization

        cfgapi.getRoot().add("*_internal_*", Setting::TypeGroup);

        auto& internal = cfgapi.getRoot()["*_internal_*"];
        auto& v = internal.add("version", Setting::TypeString);
        v = SMITH_VERSION;

        return save_status();

    }

    auto& internal = cfgapi.getRoot()["*_internal_*"];


    int our_schema = SCHEMA_VERSION;
    int cfg_schema = 1000;

    if(not load_if_exists(internal, "schema", cfg_schema)) {
        std::cerr << "schema versioning info not found, assuming 1000\n";
        internal.add("schema", libconfig::Setting::TypeInt) = 1000;
    }

    [&]{
        int num_touches = 0;

        if(our_schema > cfg_schema) {
            for (int cur_schema = cfg_schema + 1; cur_schema <= our_schema ; ++cur_schema) {
                if (upgrade_schema(cur_schema)) {
                    num_touches++;
                }
            }

            internal["schema"] = SCHEMA_VERSION;
            CfgFactory::get()->schema_version = SCHEMA_VERSION;


            if(num_touches) {
                log.event(NOT, "New configuration schema %d", our_schema);
                do_save = true;
            }
        }
    }();


    if(std::string v1; load_if_exists(internal, "version", v1)) {

        if (v1 != SMITH_VERSION) {
            backup(v1);
            upgrade_by_version(v1);

            internal["version"] = SMITH_VERSION;
            do_save = true;
        }
    } else {

        // internal section is there, but version is not... hmm.

        auto& v = internal.add("version", Setting::TypeString);
        v = SMITH_VERSION;
    }

    if(do_save) {
        return save_status();
    }

    return false;
}


bool CfgFactory::load_internal() {

    std::scoped_lock<std::recursive_mutex> l(lock_);

    if (!cfgapi.getRoot().exists("*_internal_*")) {
        Log::get()->events().insert(CRI,"error loading '*_internal_*' section");
        CfgFactory::LOAD_ERRORS = true;
        return false;
    }

    auto having_version = load_if_exists(cfgapi.getRoot()["*_internal_*"], "version", internal_version);
    auto having_schema  = load_if_exists(cfgapi.getRoot()["*_internal_*"], "schema", schema_version);

    if(not having_version) { Log::get()->events().insert(CRI,"config: internal 'version' not found"); CfgFactory::LOAD_ERRORS = true; }
    if(not having_schema) { Log::get()->events().insert(CRI,"config: internal 'schema' not found"); CfgFactory::LOAD_ERRORS = true; }

    return (having_schema and having_version);
}


bool CfgFactory::load_settings () {

    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(! cfgapi.getRoot().exists("settings"))
        return false;

    load_if_exists(cfgapi.getRoot()["settings"], "accept_tproxy", accept_tproxy);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_redirect", accept_redirect);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_socks", accept_socks);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_api", accept_api);
    load_if_exists(cfgapi.getRoot()["settings"], "plaintext_port",listen_tcp_port_base); listen_tcp_port = listen_tcp_port_base;
    load_if_exists(cfgapi.getRoot()["settings"], "plaintext_workers",num_workers_tcp);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_port",listen_tls_port_base); listen_tls_port = listen_tls_port_base;
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_workers",num_workers_tls);
    load_if_exists(cfgapi.getRoot()["settings"], "udp_port",listen_udp_port_base); listen_udp_port = listen_udp_port_base;
    load_if_exists(cfgapi.getRoot()["settings"], "udp_workers",num_workers_udp);
    load_if_exists(cfgapi.getRoot()["settings"], "dtls_port",listen_dtls_port_base);  listen_dtls_port = listen_dtls_port_base;
    load_if_exists(cfgapi.getRoot()["settings"], "dtls_workers",num_workers_dtls);


    if(cfgapi.getRoot()["settings"].exists("nameservers")) {

        if(!db_nameservers.empty()) {
            _deb("load_settings: clearing existing entries in: nameservers");
            db_nameservers.clear();
        }

        // receiver proxy will use nameservers for redirected ports
        ReceiverRedirectMap::instance().map_clear();

        const int num = cfgapi.getRoot()["settings"]["nameservers"].getLength();
        for(int i = 0; i < num; i++) {
            std::string ns = cfgapi.getRoot()["settings"]["nameservers"][i];

            CidrAddress test_ip(ns.c_str());
            if(not test_ip.cidr()) {
                _err("load_settings: nameserver %s - unknown address format", ns.c_str());
                Log::get()->events().insert(WAR, "CONFIG: settings.nameservers[%d]: '%s' - unknown address format", i, ns.c_str());
                CfgFactory::LOAD_ERRORS = true;
                continue;
            }

            AddressInfo ai;
            ai.str_host = ns;
            ai.port = 53;

            auto push_it = [&](const char* famstr) {
                if(ai.pack()) {
                    db_nameservers.push_back(ai);
                    _deb("load_settings: %s nameserver %s - added", famstr, ns.c_str());
                }
                else {
                    _err("load_settings: %s nameserver %s - cannot pack", famstr, ns.c_str());
                    Log::get()->events().insert(WAR, "CONFIG: settings.nameservers[%d]: '%s' - cannot be applied", i, famstr);
                    CfgFactory::LOAD_ERRORS = true;
                }

            };

            if(test_ip.cidr()->proto == CIDR_IPV6) {
                ai.family = AF_INET6;
                push_it("IPv6");
            }
            else if (test_ip.cidr()->proto == CIDR_IPV4) {
                ai.family = AF_INET;
                push_it("IPv4");
            }

            ReceiverRedirectMap::instance().map_add(std::stoi(listen_udp_port) + 973, ReceiverRedirectMap::redir_target_t(ns, 53));  // to make default port 51053 suggesting DNS
        }
        if(db_nameservers.empty()) {
            _cri("NO NAMESERVERS set - using defaults (Cloudflare)");
            AddressInfo ai;
            ai.family = AF_INET;
            ai.str_host = "1.1.1.1";
            ai.port = 53;
            if(ai.pack()) {
                db_nameservers.push_back(ai);
            }
            Log::get()->events().insert(NOT, "CONFIG: settings.nameservers: empty, using 1.1.1.1");
        }
    }

    load_if_exists(cfgapi.getRoot()["settings"], "certs_path",SSLFactory::factory().certs_path());
    load_if_exists(cfgapi.getRoot()["settings"], "certs_ca_key_password",SSLFactory::factory().certs_password());

    if(! load_if_exists(cfgapi.getRoot()["settings"], "certs_ctlog",SSLFactory::factory().ctlogfile())) {
        SSLFactory::factory().ctlogfile() = "/etc/smithproxy/ct_log_list.cnf";
    }


    load_if_exists(cfgapi.getRoot()["settings"], "ca_bundle_path",SSLFactory::factory().ca_path());
    load_if_exists(cfgapi.getRoot()["settings"], "ca_bundle_file", SSLFactory::factory().ca_file());

    load_if_exists(cfgapi.getRoot()["settings"], "ssl_autodetect",MitmMasterProxy::ssl_autodetect);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_autodetect_harder",MitmMasterProxy::ssl_autodetect_harder);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_ocsp_status_ttl",SSLFactory::options::ocsp_status_ttl);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_crl_status_ttl",SSLFactory::options::crl_status_ttl);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_use_ktls",SSLFactory::options::ktls);

    if(cfgapi.getRoot()["settings"].exists("udp_quick_ports")) {

        if(!db_udp_quick_ports.empty()) {
            _deb("load_settings: clearing existing entries in: udp_quick_ports");
            db_udp_quick_ports.clear();
        }

        int num = cfgapi.getRoot()["settings"]["udp_quick_ports"].getLength();
        for(int i = 0; i < num; ++i) {
            int port = cfgapi.getRoot()["settings"]["udp_quick_ports"][i];
            db_udp_quick_ports.push_back(port);
        }
    }

    load_if_exists(cfgapi.getRoot()["settings"], "socks_port",listen_socks_port_base); listen_socks_port = listen_socks_port_base;
    load_if_exists(cfgapi.getRoot()["settings"], "socks_workers",num_workers_socks);

    if(cfgapi.getRoot().exists("settings")) {
        if(cfgapi.getRoot()["settings"].exists("socks")) {
            load_if_exists(cfgapi.getRoot()["settings"]["socks"], "async_dns", socksServerCX::global_async_dns);
            load_if_exists(cfgapi.getRoot()["settings"]["socks"], "ipver_mixing", socksServerCX::mixed_ip_versions);
            load_if_exists(cfgapi.getRoot()["settings"]["socks"], "prefer_ipv6", socksServerCX::prefer_ipv6);
        }
    }

    load_if_exists_atomic(cfgapi.getRoot()["settings"], "log_level", CfgFactory::get()->internal_init_level.level_ref());

    load_if_exists(cfgapi.getRoot()["settings"], "syslog_server", syslog_server);
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_port", syslog_port);
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_facility", syslog_facility);
    load_if_exists_atomic(cfgapi.getRoot()["settings"], "syslog_level", syslog_level.level_ref());
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_family", syslog_family);

    load_if_exists(cfgapi.getRoot()["settings"], "messages_dir", dir_msg_templates);

    if(cfgapi.getRoot()["settings"].exists("cli")) {
        load_if_exists<int>(cfgapi.getRoot()["settings"]["cli"], "port", CfgFactory::get()->cli_port_base);
        CfgFactory::get()->cli_port = CfgFactory::get()->cli_port_base;

        load_if_exists(cfgapi.getRoot()["settings"]["cli"], "enable_password", CfgFactory::get()->cli_enable_password);
    }

    if(cfgapi.getRoot()["settings"].exists("admin")) {
        load_if_exists(cfgapi.getRoot()["settings"]["admin"], "group", admin_group);
    }

    if(cfgapi.getRoot()["settings"].exists("auth_portal")) {
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "address", auth_address);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "http_port", auth_http);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "https_port", auth_https);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "ssl_key", auth_sslkey);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "ssl_cert", auth_sslcert);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "magic_ip", tenant_magic_ip);
    }

    if(cfgapi.getRoot()["settings"].exists("tuning")) {
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "proxy_thread_spray_min", MasterProxy::subproxy_thread_spray_min);
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "subproxy_thread_spray_bytes_min", MasterProxy::subproxy_thread_spray_bytes_min);

        int hostcx_min = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_bufsz_min", hostcx_min);
        if(hostcx_min >= 1500 and hostcx_min < 10000000) { baseHostCX::params.buffsize = hostcx_min; } // maximum initial bufsize is guarded at 10MB

        int hostcx_maxmul = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_bufsz_max_multiplier", hostcx_maxmul);
        if(hostcx_maxmul > 0) { baseHostCX::params.buffsize_maxmul = hostcx_maxmul; }

        int hostcx_write_full = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_write_full", hostcx_write_full);
        if(hostcx_write_full >= 1024) { baseHostCX::params.write_full = hostcx_write_full; }

    }

    if(cfgapi.getRoot()["settings"].exists("http_api")) {
        auto& key_storage = sx::webserver::HttpSessions::api_keys;

        if(not key_storage.empty()) {
            _deb("load_settings: clearing existing entries in: api keys");
            key_storage.clear();
        }

        if(cfgapi.getRoot()["settings"]["http_api"].exists("keys")) {
            const int num = cfgapi.getRoot()["settings"]["http_api"]["keys"].getLength();
            for (int i = 0; i < num; i++) {
                std::string key = cfgapi.getRoot()["settings"]["http_api"]["keys"][i];
                key_storage.emplace(key);
            }
        }
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "key_timeout", sx::webserver::HttpSessions::session_ttl);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "key_extend_on_access", sx::webserver::HttpSessions::extend_on_access);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "loopback_only", sx::webserver::HttpSessions::loopback_only);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "bind_address", sx::webserver::HttpSessions::bind_address);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "bind_interface", sx::webserver::HttpSessions::bind_interface);

        if(cfgapi.getRoot()["settings"]["http_api"].exists("allowed_ips")) {
            sx::webserver::HttpSessions::allowed_ips.clear();
            const int num = cfgapi.getRoot()["settings"]["http_api"]["allowed_ips"].getLength();
            for (int i = 0; i < num; i++) {
                std::string ip = cfgapi.getRoot()["settings"]["http_api"]["allowed_ips"][i];
                sx::webserver::HttpSessions::allowed_ips.emplace_back(ip);
            }
        }

        int api_port = 55555;
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "port", api_port);
        if(api_port < 1025 or api_port >= 65535)  {
            log.event(ERR, "invalid API port number");
            sx::webserver::HttpSessions::api_port = 55555;
            Log::get()->events().insert(WAR, "CONFIG: settings.http_api.port: invalid port value, using 55555");
            CfgFactory::LOAD_ERRORS = true;
        }
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "pam_login", sx::webserver::HttpSessions::pam_login);
    }

    if(cfgapi.getRoot()["settings"].exists("webhook")) {

        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "enabled", settings_webhook.enabled);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "url", settings_webhook.cfg_url);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "tls_verify", settings_webhook.cfg_tls_verify);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "api_override", settings_webhook.allow_api_override);

        sx::http::webhooks::set_enabled(settings_webhook.enabled);

        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "hostid", settings_webhook.hostid);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "bind_interface", settings_webhook.bind_interface);
        if(not settings_webhook.hostid.empty()) sx::http::webhooks::set_hostid(settings_webhook.hostid);
    }

    return true;
}

#ifdef USE_EXPERIMENT
bool CfgFactory::load_experiment() {

    if(cfgapi.getRoot().exists("experiment")) {
        load_if_exists(cfgapi.getRoot()["experiment"], "enabled_1", experiment_1.enabled);
        load_if_exists(cfgapi.getRoot()["experiment"], "param_1", experiment_1.param);
    }

    return true;
}
#endif


bool CfgFactory::load_captures() {

    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto factory = CfgFactory::get();

    if(cfgapi.getRoot().exists("captures")) {
        Setting const& captures = cfgapi.getRoot()["captures"];

        if(captures.exists("local")) {
            Setting const& local = captures["local"];

            load_if_exists(local, "enabled", factory->capture_local.enabled);
            load_if_exists(local, "dir", factory->capture_local.dir);
            load_if_exists(local, "file_prefix", factory->capture_local.file_prefix);
            load_if_exists(local, "file_suffix", factory->capture_local.file_suffix);

            std::string fmt_str;
            if(load_if_exists(local, "format", fmt_str)) {
                factory->capture_local.format = fmt_str;

                if (fmt_str == "pcap_single") {
                    auto fs = factory->capture_local.format.to_ext(factory->capture_local.file_suffix);
                    auto fp = factory->capture_local.file_prefix;
                    auto fd = factory->capture_local.dir;
                    auto only_remote = not factory->capture_local.enabled;

                    auto& tgt = traflog::PcapLog::single_instance();
                    bool updated = false;

                    if(tgt.FS.file_suffix != fs) { tgt.FS.file_suffix = fs; updated = true; }
                    if(tgt.FS.file_prefix != fp) { tgt.FS.file_prefix = fp; updated = true; }
                    if(tgt.FS.data_dir != fd) { tgt.FS.data_dir = fd; updated = true; }
                    if(traflog::PcapLog::ip_packet_hook_only != only_remote ) { traflog::PcapLog::ip_packet_hook_only = only_remote; }

                    if(updated) {
                        traflog::PcapLog::single_instance().FS.generate_filename_single("smithproxy", true);
                        traflog::PcapLog::single_instance().pcap_header_written = false;
                    }
                }
            }

            int quota_megabytes;
            load_if_exists(local, "pcap_quota", quota_megabytes);

            if(fmt_str == "pcap_single")
                traflog::PcapLog::single_instance().stat_bytes_quota = quota_megabytes*1024*1024;
        }
        if(captures.exists("remote")) {
            Setting const& remote = captures["remote"];

            load_if_exists(remote, "enabled", CfgFactory::get()->capture_remote.enabled);
            load_if_exists(remote, "tun_type", CfgFactory::get()->capture_remote.tun_type);
            load_if_exists(remote, "tun_dst", CfgFactory::get()->capture_remote.tun_dst);
            load_if_exists(remote, "tun_ttl", CfgFactory::get()->capture_remote.tun_ttl);

            CfgFactory::gre_export_apply(&traflog::PcapLog::single_instance());
        }
        if(captures.exists("options")) {
            Setting const& remote = captures["options"];
            load_if_exists(remote, "calculate_checksums", socle::pcap::CONFIG::CALCULATE_CHECKSUMS);
        }
    }
    else {
        // try to load old variables

        load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_dir", CfgFactory::get()->capture_local.dir);
        load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_file_prefix", CfgFactory::get()->capture_local.file_prefix);
        load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_file_suffix", CfgFactory::get()->capture_local.file_suffix);

        int quota_megabytes;
        load_if_exists(CfgFactory::cfg_root()["settings"], "write_pcap_single_quota", quota_megabytes);
        traflog::PcapLog::single_instance().stat_bytes_quota = quota_megabytes*1024*1024;

    }

    return true;
}

int CfgFactory::load_debug() {

    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(cfgapi.getRoot().exists("debug")) {

        load_if_exists(CfgFactory::cfg_root()["debug"], "log_data_crc", baseCom::debug_log_data_crc);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_sockets", baseHostCX::socket_in_name);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_online_cx_name", baseHostCX::online_name);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_srclines", Log::get()->print_srcline());
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_srclines_always", Log::get()->print_srcline_always());

        if (cfgapi.getRoot()["debug"].exists("log")) {

            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "sslcom", SSLCom::log_level().level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "sslmitmcom",
                                                               baseSSLMitmCom<SSLCom>::log_level().level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "sslmitmcom",
                                                               baseSSLMitmCom<DTLSCom>::log_level().level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "sslcertstore",
                                                               SSLFactory::get_log().level()->level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "proxy", baseProxy::log_level().level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "proxy", epoll::log_level.level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "mtrace", cfg_mtrace_enable);
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "openssl_mem_dbg", cfg_openssl_mem_dbg);

            /*DNS ALG EXPLICIT LOG*/
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "alg_dns", DNS_Inspector::log_level().level_ref());
            load_if_exists_atomic(CfgFactory::cfg_root()["debug"]["log"], "alg_dns", DNS_Packet::log_level().level_ref());
        }
        return 1;
    }

    return -1;
}

int CfgFactory::load_db_address () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;
    
    _dia("cfgapi_load_addresses: start");
    
    if(cfgapi.getRoot().exists("address_objects")) {

        num = cfgapi.getRoot()["address_objects"].getLength();
        _dia("cfgapi_load_addresses: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["address_objects"];

        for( int i = 0; i < num; i++) {

            Setting &cur_object = curr_set[i];

            if (!cur_object.getName()) {
                _dia("cfgapi_load_address: unnamed object index %d: not ok", i);
                continue;
            }

            std::string name;
            name = cur_object.getName();
            if (name.find("__") == 0) {
                // don't process reserved names
                continue;
            }

            auto load_addr_09_30 = [&]() {

                std::string address;
                int type;

                _deb("cfgapi_load_addresses: processing '%s'", name.c_str());

                if (load_if_exists(cur_object, "type", type)) {
                    switch (type) {
                        case 0: // CIDR notation
                            if (load_if_exists(cur_object, "cidr", address)) {
                                auto *c = cidr::cidr_from_str(address.c_str());

                                db_address[name] = std::make_shared<CfgAddress>(
                                        std::shared_ptr<AddressObject>(new CidrAddress(c)));
                                db_address[name]->element_name() = name;
                                _dia("cfgapi_load_addresses: cidr '%s': ok", name.c_str());
                            }
                            break;
                        case 1: // FQDN notation
                            if (load_if_exists(cur_object, "fqdn", address)) {

                                db_address[name] = std::make_shared<CfgAddress>(
                                        std::shared_ptr<AddressObject>(new FqdnAddress(address)));
                                db_address[name]->element_name() = name;
                                _dia("cfgapi_load_addresses: fqdn '%s': ok", name.c_str());
                            }
                            break;
                        default:
                            _dia("cfgapi_load_addresses: fqdn '%s': unknown type value(ignoring)", name.c_str());
                    }
                } else {
                    _dia("cfgapi_load_addresses: '%s': not ok", name.c_str());
                }
            };

            auto load_addr = [&]() {

                std::string address;
                std::string type;

                _deb("cfgapi_load_addresses: processing '%s'", name.c_str());

                if (not load_if_exists(cur_object, "type", type)) {
                    _dia("cfgapi_load_addresses: '%s': not ok", name.c_str());

                    Log::get()->events().insert(WAR, "CONFIG: address: '%s': 'type' attribute is missing", name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    return;
                }

                if(type == "cidr") {
                    if (load_if_exists(cur_object, "value", address)) {
                        auto *c = cidr::cidr_from_str(address.c_str());

                        db_address[name] = std::make_shared<CfgAddress>(
                                std::shared_ptr<AddressObject>(new CidrAddress(c)));
                        db_address[name]->element_name() = name;
                        _dia("cfgapi_load_addresses: cidr '%s': ok", name.c_str());
                    }
                }
                else if(type == "fqdn") {
                    if (load_if_exists(cur_object, "value", address)) {

                        db_address[name] = std::make_shared<CfgAddress>(
                                std::shared_ptr<AddressObject>(new FqdnAddress(address)));
                        db_address[name]->element_name() = name;
                        _dia("cfgapi_load_addresses: fqdn '%s': ok", name.c_str());
                    }
                }
                else {
                    _dia("cfgapi_load_addresses: '%s': unknown type value", name.c_str());
                    Log::get()->events().insert(WAR, "CONFIG: address: '%s': unknown type '%s'", name.c_str(), type.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                }
            };

            // since 0.9.31 cidr objects have different config syntax:
            // OLD = {
            //     type = <int>
            //     cidr = "cidr_string" ; if type = 0
            //     fqdn = "fqdn_string" ; if type = 1
            // }
            // NEW = {
            //     type = <string>  ; "cidr" or "fqdn"
            //     value = "value"
            // }

            // detect config style version, value is present in new scheme
            if(cur_object.exists("value")) {
                load_addr();
            }
            else {
                load_addr_09_30();
            }

        }
    }
    
    return num;
}

int CfgFactory::load_db_port () {
    
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_ports: start");
    
    if(cfgapi.getRoot().exists("port_objects")) {

        num = cfgapi.getRoot()["port_objects"].getLength();
        _dia("cfgapi_load_ports: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["port_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            int a;
            int b;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_ports: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();

            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }

            _deb("cfgapi_load_ports: processing '%s'", name.c_str());
            
            if( load_if_exists(cur_object, "start", a) &&
                    load_if_exists(cur_object, "end", b)   ) {
                
                if(a <= b) {
                    auto cf = std::make_shared<CfgRange>(std::pair(a, b));
                    cf->element_name() = name;
                    db_port[name] = cf;
                } else {
                    auto cf = std::make_shared<CfgRange>(std::pair(b, a));
                    cf->element_name() = name;
                    db_port[name] = cf;
                }

                _dia("cfgapi_load_ports: '%s': ok", name.c_str());
            } else {
                _dia("cfgapi_load_ports: '%s': not ok", name.c_str());
                Log::get()->events().insert(WAR, "CONFIG: port: '%s': missing `start` or `end`", name.c_str());
                CfgFactory::LOAD_ERRORS = true;
            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_proto () {
    
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_proto: start");
    
    if(cfgapi.getRoot().exists("proto_objects")) {

        num = cfgapi.getRoot()["proto_objects"].getLength();
        _dia("cfgapi_load_proto: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["proto_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_proto: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();

            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }

            _deb("cfgapi_load_proto: processing '%s'", name.c_str());

            int ia;
            if( load_if_exists(cur_object, "id", ia) ) {

                auto a = std::make_shared<CfgUint8>(static_cast<uint8_t>(ia));
                a->element_name() = name;

                db_proto[name] = a;

                _dia("cfgapi_load_proto: '%s': ok", name.c_str());
            } else {
                _dia("cfgapi_load_proto: '%s': not ok", name.c_str());
                Log::get()->events().insert(WAR, "CONFIG: proto: '%s': missing `id`", name.c_str());
                CfgFactory::LOAD_ERRORS = true;

            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_features() {
    auto lc_ = std::scoped_lock(lock_);

    _dia("cfgapi_load_db_filters: start");
    auto sl = std::make_shared<CfgString>("sink-left");
    db_features["sink-left"] = std::move(sl);
    db_features["sink-left"]->element_name() = "sink-left";

    auto sr = std::make_shared<CfgString>("sink-right");
    db_features["sink-right"] = std::move(sr);
    db_features["sink-right"]->element_name() = "sink-right";

    auto sa = std::make_shared<CfgString>("sink-all");
    db_features["sink-all"] = std::move(sa);
    db_features["sink-all"]->element_name() = "sink-all";


    auto statistics = std::make_shared<CfgString>("statistics");
    db_features["statistics"] = std::move(statistics);
    db_features["statistics"]->element_name() = "statistics";

    auto access_request = std::make_shared<CfgString>("access-request");
    db_features["access-request"] = std::move(access_request);
    db_features["access-request"]->element_name() = "access-request";

    return static_cast<int>(db_features.size());
}

int CfgFactory::load_db_policy () {

    auto err_event = [&](int policy_index, const char* info) {
        Log::get()->events().insert(ERR, "CONFIG: policy[%d]: not loaded, error: %s", policy_index, info);
    };
    auto war_event = [&](int policy_index, const char* info) {
        Log::get()->events().insert(WAR, "CONFIG: policy[%d]: loaded with warning: %s", policy_index, info);
    };


    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_policy: start");
    
    if(cfgapi.getRoot().exists("policy")) {

        num = cfgapi.getRoot()["policy"].getLength();
        _dia("cfgapi_load_policy: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["policy"];

        for(int policy_index = 0; policy_index < num; policy_index++) {
            Setting& cur_object = curr_set[policy_index];

            bool this_disabled = false;
            std::string proto;
            std::string dst;
            std::string dport;
            std::string src;
            std::string sport;
            std::string profile_detection;
            std::string profile_content;
            std::string action;
            std::string nat;
            
            bool hard_error = false;
            bool soft_error = false;

            _dia("cfgapi_load_policy: processing #%d", policy_index);
            
            auto rule = std::make_shared<PolicyRule>();

            if(load_if_exists(cur_object, "disabled", this_disabled)) {
                rule->is_disabled = this_disabled;
            }

            load_if_exists(cur_object, "name", rule->policy_name);

            if(load_if_exists(cur_object, "proto", proto)) {
                auto r = lookup_proto(proto.c_str());
                if(r) {
                    r->usage_add(std::weak_ptr(rule));
                    rule->proto = r;
                    _dia("cfgapi_load_policy[#%d]: proto object: %s", policy_index, proto.c_str());
                } else {
                    _dia("cfgapi_load_policy[#%d]: proto object not found: %s", policy_index, proto.c_str());
                    hard_error = true;

                    err_event(policy_index, string_format("proto object not found: '%s'", proto.c_str()).c_str());
                }
            }
            
            const Setting& sett_src = cur_object["src"];
            if(sett_src.isScalar()) {
                _dia("cfgapi_load_policy[#%d]: scalar src address object", policy_index);
                if(load_if_exists(cur_object, "src", src)) {
                    
                    auto r = lookup_address(src.c_str());
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: src address object: %s", policy_index, src.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src address object not found: %s", policy_index, src.c_str());
                        hard_error = true;

                        err_event(policy_index, string_format("src object not found: '%s'", src.c_str()).c_str());
                    }
                }
            } else {
                int sett_src_count = sett_src.getLength();
                _dia("cfgapi_load_policy[#%d]: src address list", policy_index);
                for(int y = 0; y < sett_src_count; y++) {
                    const char* obj_name = sett_src[y];
                    
                    auto r = lookup_address(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: src address object: %s", policy_index, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src address object not found: %s", policy_index, obj_name);
                        hard_error = true;

                        err_event(policy_index, string_format("src object not found: '%s'", src.c_str()).c_str());
                    }

                }
            }
            
            const Setting& sett_sport = cur_object["sport"];
            if(sett_sport.isScalar()) {
                if(load_if_exists(cur_object, "sport", sport)) {
                    auto r = lookup_port(sport.c_str());
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: src_port object: %s", policy_index, sport.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src_port object not found: %s", policy_index, sport.c_str());
                        hard_error = true;

                        err_event(policy_index, string_format("src_port object not found: '%s'", sport.c_str()).c_str());
                    }
                }
            } else {
                int sett_sport_count = sett_sport.getLength();
                _dia("cfgapi_load_policy[#%d]: sport list", policy_index);
                for(int y = 0; y < sett_sport_count; y++) {
                    const char* obj_name = sett_sport[y];
                    
                    auto r = lookup_port(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: src_port object: %s", policy_index, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src_port object not found: %s", policy_index, obj_name);
                        hard_error = true;

                        err_event(policy_index, string_format("src_port object not found: '%s'", sport.c_str()).c_str());
                    }
                }
            }

            const Setting& sett_dst = cur_object["dst"];
            if(sett_dst.isScalar()) {
                if(load_if_exists(cur_object, "dst", dst)) {
                    auto r = lookup_address(dst.c_str());
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst address object: %s", policy_index, dst.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst address object not found: %s", policy_index, dst.c_str());
                        hard_error = true;

                        err_event(policy_index, string_format("dst address object not found: '%s'", dst.c_str()).c_str());
                    }                
                }
            } else {
                int sett_dst_count = sett_dst.getLength();
                _dia("cfgapi_load_policy[#%d]: dst list", policy_index);
                for(int y = 0; y < sett_dst_count; y++) {
                    const char* obj_name = sett_dst[y];

                    auto r = lookup_address(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst address object: %s", policy_index, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst address object not found: %s", policy_index, obj_name);
                        hard_error = true;

                        err_event(policy_index, string_format("dst address object not found: '%s'", dst.c_str()).c_str());
                    }                
                }
            }
            
            
            const Setting& sett_dport = cur_object["dport"];
            if(sett_dport.isScalar()) { 
                if(load_if_exists(cur_object, "dport", dport)) {
                    auto r = lookup_port(dport.c_str());
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst_port object: %s", policy_index, dport.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst_port object not found: %s", policy_index, dport.c_str());
                        hard_error = true;

                        err_event(policy_index, string_format("dst port object not found: '%s'", dport.c_str()).c_str());
                    }
                }
            } else {
                int sett_dport_count = sett_dport.getLength();
                _dia("cfgapi_load_policy[#%d]: dst_port object list", policy_index);
                for(int y = 0; y < sett_dport_count; y++) {
                    const char* obj_name = sett_dport[y];
                    
                    auto r = lookup_port(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst_port object: %s", policy_index, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst_port object not found: %s", policy_index, obj_name);
                        hard_error = true;

                        err_event(policy_index, string_format("dst port object not found: '%s'", dport.c_str()).c_str());
                    }                    
                }
            }

            if(cur_object.exists("features")) {
                const Setting &sett_features = cur_object["features"];
                if (not sett_features.isScalar()) {
                    int sett_filters_count = sett_features.getLength();
                    _dia("cfgapi_load_policy[#%d]: features object list", policy_index);
                    for (int y = 0; y < sett_filters_count; y++) {
                        const char *obj_name = sett_features[y];

                        auto r = lookup_features(obj_name);
                        if (r) {
                            r->usage_add(std::weak_ptr(rule));
                            rule->features.emplace_back(r);
                            _dia("cfgapi_load_policy[#%d]: features object: %s", policy_index, obj_name);
                        } else {
                            _dia("cfgapi_load_policy[#%d]: features object not found: %s", policy_index, obj_name);
                            hard_error = true;

                            err_event(policy_index, string_format("features object not found: '%s'", obj_name).c_str());
                        }
                    }
                }
            }
            
            if(load_if_exists(cur_object, "action", action)) {
                int r_a = PolicyRule::POLICY_ACTION_PASS;
                if(action == "deny") {
                    _dia("cfgapi_load_policy[#%d]: action: deny", policy_index);
                    r_a = PolicyRule::POLICY_ACTION_DENY;
                    rule->action_name = action;

                } else if (action == "accept"){
                    _dia("cfgapi_load_policy[#%d]: action: accept", policy_index);
                    r_a = PolicyRule::POLICY_ACTION_PASS;
                    rule->action_name = action;
                } else {
                    _dia("cfgapi_load_policy[#%d]: action: unknown action '%s'", policy_index, action.c_str());
                    r_a  = PolicyRule::POLICY_ACTION_DENY;
                    hard_error = true;
                    war_event(policy_index, string_format("unknown action name: '%s'",action.c_str()).c_str());
                }
                
                rule->action = r_a;
            } else {
                rule->action = PolicyRule::POLICY_ACTION_DENY;
                rule->action_name = "deny";
            }

            if(load_if_exists(cur_object, "nat", nat)) {
                int nat_a = PolicyRule::POLICY_NAT_NONE;
                
                if(nat == "none") {
                    _dia("cfgapi_load_policy[#%d]: nat: none", policy_index);
                    nat_a = PolicyRule::POLICY_NAT_NONE;
                    rule->nat_name = nat;

                } else if (nat == "auto"){
                    _dia("cfgapi_load_policy[#%d]: nat: auto", policy_index);
                    nat_a = PolicyRule::POLICY_NAT_AUTO;
                    rule->nat_name = nat;
                } else {
                    _dia("cfgapi_load_policy[#%d]: nat: unknown nat method '%s'", policy_index, nat.c_str());
                    nat_a  = PolicyRule::POLICY_NAT_NONE;
                    rule->nat_name = "none";
                    hard_error = true;
                    war_event(policy_index, string_format("unknown nat method: '%s'",nat.c_str()).c_str());
                }
                
                rule->nat = nat_a;
            } else {
                rule->nat = PolicyRule::POLICY_NAT_NONE;
            }            
            
            
            /* try to load policy profiles */
            
            if(rule->action == 1) {
                // makes sense to load profiles only when action is accept! 
                std::string name_content;
                std::string name_detection;
                std::string name_tls;
                std::string name_auth;
                std::string name_alg_dns;
                std::string name_script;
                std::string name_routing;

                if(load_if_exists(cur_object, "detection_profile", name_detection)) {
                    auto prf  = lookup_prof_detection(name_detection.c_str());
                    if(prf) {
                        prf->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: detect profile %s", policy_index, name_detection.c_str());
                        rule->profile_detection = std::shared_ptr<ProfileDetection>(prf);
                    }
                    else if(not name_detection.empty()) {
                        _err("cfgapi_load_policy[#%d]: detect profile %s cannot be loaded", policy_index, name_detection.c_str());
                        soft_error = true;

                        war_event(policy_index, string_format("detection_profile not loaded: '%s'",name_detection.c_str()).c_str());
                    }
                }
                
                if(load_if_exists(cur_object, "content_profile", name_content)) {
                    auto prf  = lookup_prof_content(name_content.c_str());
                    if(prf) {
                        prf->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: content profile %s", policy_index, name_content.c_str());
                        rule->profile_content = prf;
                    }
                    else if(not name_content.empty()) {
                        _err("cfgapi_load_policy[#%d]: content profile %s cannot be loaded", policy_index, name_content.c_str());
                        soft_error = true;

                        war_event(policy_index, string_format("content_profile not loaded: '%s'",name_content.c_str()).c_str());
                    }
                }                
                if(load_if_exists(cur_object, "tls_profile", name_tls)) {
                    auto tls  = lookup_prof_tls(name_tls.c_str());
                    if(tls) {
                        tls->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: tls profile %s", policy_index, name_tls.c_str());
                        rule->profile_tls= std::shared_ptr<ProfileTls>(tls);
                    }
                    else if(not name_tls.empty()){
                        _err("cfgapi_load_policy[#%d]: tls profile %s cannot be loaded", policy_index, name_tls.c_str());
                        soft_error = true;

                        war_event(policy_index, string_format("tls_profile not loaded: '%s'",name_tls.c_str()).c_str());
                    }
                }         
                if(load_if_exists(cur_object, "auth_profile", name_auth)) {
                    auto auth  = lookup_prof_auth(name_auth.c_str());
                    if(auth) {
                        auth->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: auth profile %s", policy_index, name_auth.c_str());
                        rule->profile_auth= auth;
                    }
                    else if(not name_auth.empty()) {
                        _err("cfgapi_load_policy[#%d]: auth profile %s cannot be loaded", policy_index, name_auth.c_str());
                        soft_error = true;

                        war_event(policy_index, string_format("auth_profile not loaded: '%s'",name_auth.c_str()).c_str());
                    }
                }
                if(load_if_exists(cur_object, "alg_dns_profile", name_alg_dns)) {
                    auto dns  = lookup_prof_alg_dns(name_alg_dns.c_str());
                    if(dns) {
                        dns->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: DNS alg profile %s", policy_index, name_alg_dns.c_str());
                        rule->profile_alg_dns = dns;
                    }
                    else if(not name_alg_dns.empty()) {
                        _err("cfgapi_load_policy[#%d]: DNS alg %s cannot be loaded", policy_index, name_alg_dns.c_str());
                        soft_error = true;

                        war_event(policy_index, string_format("alg_dns_profile not loaded: '%s'",name_alg_dns.c_str()).c_str());
                    }
                }

                if(load_if_exists(cur_object, "script_profile", name_script)) {
                    auto scr  = lookup_prof_script(name_script.c_str());
                    if(scr) {
                        scr->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: script profile %s", policy_index, name_script.c_str());
                        rule->profile_script = scr;
                    }
                    else if(not name_script.empty()){
                        _err("cfgapi_load_policy[#%d]: script profile %s cannot be loaded", policy_index, name_script.c_str());
                        soft_error = true;
                        war_event(policy_index, string_format("script_profile not loaded: '%s'",name_script.c_str()).c_str());
                    }
                }

                if(load_if_exists(cur_object, "routing", name_routing)) {

                    if(name_routing.empty()) name_routing = "none";

                    if(name_routing != "none") {
                        auto scr = lookup_prof_routing(name_routing.c_str());
                        if (scr) {
                            scr->usage_add(std::weak_ptr(rule));
                            _dia("cfgapi_load_policy[#%d]: routing profile %s", policy_index, name_routing.c_str());
                            rule->profile_routing = scr;
                        } else if (not name_routing.empty()) {
                            _err("cfgapi_load_policy[#%d]: routing profile %s cannot be loaded", policy_index,
                                 name_routing.c_str());
                            soft_error = true;

                            war_event(policy_index, string_format("routng not loaded: '%s'",name_routing.c_str()).c_str());
                        }
                    }
                }


            }


            if(not hard_error) {
                if(soft_error) {
                    _dia("cfgapi_load_policy[#%d]: loaded with a soft error", policy_index);
                    rule->cfg_err_is_degraded = true;
                } else {
                    _dia("cfgapi_load_policy[#%d]: ok", policy_index);
                }
            } else {
                rule->cfg_err_is_disabled = true;
                _err("cfgapi_load_policy[#%d]: not ok, disabled", policy_index);

            }

            if(hard_error or soft_error) LOAD_ERRORS = true;

            db_policy_list.push_back(rule);
            db_policy[string_format("[%d]", policy_index)] = rule;
        }
    }
    
    return num;
}

int CfgFactory::policy_match (baseProxy *proxy) {

    auto const& log = log::policy();

    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int x = 0;
    for( auto const& rule: db_policy_list) {

        bool r = rule->match(proxy);
        
        if(r) {
            _deb("policy_match: matched #%d", x);

            {
                // shadowing own log desired - wanting to log in policy rule context
                _dia(" => policy #%d matched!", x);
            }

            return x;
        } else {
            // shadowing own log desired - wanting to log in policy rule context
            _dia(" => policy #%d NOT matched!", x);
        }
        
        x++;
    }

    _not("policy_match: implicit deny");
    return -1;
}

int CfgFactory::policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int x = 0;
    for( auto const& rule: db_policy_list) {

        bool r = rule->match(left, right);
        
        if(r) {
            _dia("cfgapi_obj_policy_match_lr: matched #%d", x);

            {
                // shadowing own log desired - wanting to log in policy rule context
                auto &log = rule->get_log();
                _dia(" => policy #%d matched!", x);
            }

            return x;
        } else {
            // shadowing own log desired - wanting to log in policy rule context
            auto &log = rule->get_log();
            _dia(" => policy #%d NOT matched!", x);
        }

        
        x++;
    }

    _dia("cfgapi_obj_policy_match_lr: implicit deny");
    return -1;
}    

int CfgFactory::policy_action (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return -1;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->action;
    } else {
        _dia("cfg_obj_policy_action[#%d]: out of bounds, deny", index);
        return PolicyRule::POLICY_ACTION_DENY;
    }
}

std::shared_ptr<PolicyRule> CfgFactory::policy_rule (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(index < 0) {
        return nullptr;
    }

    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index);
    } else {
        _dia("cfg_obj_policy_rule[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}


std::shared_ptr<ProfileContent> CfgFactory::policy_prof_content (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_content;
    } else {
        _dia("policy_prof_content[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}

std::shared_ptr<ProfileDetection> CfgFactory::policy_prof_detection (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_detection;
    } else {
        _dia("policy_prof_detection[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}

std::shared_ptr<ProfileTls> CfgFactory::policy_prof_tls (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_tls;
    } else {
        _dia("policy_prof_tls[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}


std::shared_ptr<ProfileAlgDns> CfgFactory::policy_prof_alg_dns (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_alg_dns;
    } else {
        _dia("policy_prof_alg_dns[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}

[[maybe_unused]]
std::shared_ptr<ProfileScript> CfgFactory::policy_prof_script(int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(index < 0) {
        return nullptr;
    }

    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_script;
    } else {
        _dia("policy_prof_alg_dns[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}



std::shared_ptr<ProfileAuth> CfgFactory::policy_prof_auth (int index) {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return nullptr;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->profile_auth;
    } else {
        _dia("policy_prof_auth[#%d]: out of bounds, nullptr", index);
        return nullptr;
    }
}



int CfgFactory::load_db_prof_detection () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_obj_profile_detect: start");
    
    if(cfgapi.getRoot().exists("detection_profiles")) {

        num = cfgapi.getRoot()["detection_profiles"].getLength();
        _dia("cfgapi_load_obj_profile_detect: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["detection_profiles"];
        
        for( int i = 0; i < num; i++) {
            std::string name;
            auto new_prof = std::make_unique<ProfileDetection>();
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_obj_profile_detect: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _dia("cfgapi_load_obj_profile_detect: processing '%s'", name.c_str());
            
            if( load_if_exists(cur_object, "mode", new_prof->mode) ) {

                new_prof->element_name() = name;
                load_if_exists(cur_object, "engines_enabled", new_prof->engines_enabled);
                load_if_exists(cur_object, "kb_enabled", new_prof->kb_enabled);

                db_prof_detection[name] = std::shared_ptr<ProfileDetection>(std::move(new_prof));

                _dia("cfgapi_load_obj_profile_detect: '%s': ok", name.c_str());
            } else {
                _dia("cfgapi_load_obj_profile_detect: '%s': not ok", name.c_str());
                Log::get()->events().insert(WAR,"CONFIG: detection_profile '%s': missing 'mode' attribute", cur_object.getName());
                CfgFactory::LOAD_ERRORS = true;

            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_prof_content_subrules(Setting& cur_object, ProfileContent* new_profile) {
    int jnum = cur_object["content_rules"].getLength();
    _dia("replace rules in profile '%s', size %d", new_profile->element_name().c_str(), jnum);
    for (int j = 0; j < jnum; j++) {
        Setting &cur_replace_rule = cur_object["content_rules"][j];

        std::string m;
        std::string r;
        bool action_defined = false;

        bool fill_length = false;
        int replace_each_nth = 0;

        load_if_exists(cur_replace_rule, "match", m);

        if (load_if_exists(cur_replace_rule, "replace", r)) {
            action_defined = true;
        }

        load_if_exists(cur_replace_rule, "fill_length", fill_length);
        load_if_exists(cur_replace_rule, "replace_each_nth", replace_each_nth);

        if ((!m.empty()) && action_defined) {
            _dia("    [%d] match '%s' and replace with '%s'", j, m.c_str(), r.c_str());
            ProfileContentRule p;
            p.match = m;
            p.replace = r;
            p.fill_length = fill_length;
            p.replace_each_nth = replace_each_nth;

            new_profile->content_rules.push_back(p);

        } else {
            _dia("    [%d] unfinished replace policy", j);
            Log::get()->events().insert(WAR,"CONFIG: content_profile[%s/%d]: unfinished sub-rules", cur_object.getName(),j);
            CfgFactory::LOAD_ERRORS = true;
        }
    }

    return jnum;
};


bool CfgFactory::load_db_prof_content_write_format(Setting& cur_object, ProfileContent* new_profile) {
    std::string write_format = "pcap_single";
    load_if_exists(cur_object, "write_format", write_format);
    write_format = string_tolower(write_format);

    new_profile->write_format = ContentCaptureFormat(write_format);

    return true;

}

int CfgFactory::load_db_prof_content () {
    std::scoped_lock<std::recursive_mutex> l(lock_);


    _dia("load_db_prof_content: start");
    if(not cfgapi.getRoot().exists("content_profiles")) return 0;


    int num = cfgapi.getRoot()["content_profiles"].getLength();
    _dia("load_db_prof_content: found %d objects", num);

    Setting const& curr_set = cfgapi.getRoot()["content_profiles"];

    for( int i = 0; i < num; i++) {
        std::string name;
        auto new_profile = std::make_shared<ProfileContent>();

        Setting& cur_object = curr_set[i];

        if ( not cur_object.getName() ) {
            _dia("load_db_prof_content: unnamed object index %d: not ok", i);
            continue;
        }

        name = cur_object.getName();
        if(name.find("__") == 0) {
            // don't process reserved names
            continue;
        }

        _dia("load_db_prof_content: processing '%s'", name.c_str());

        if( load_if_exists(cur_object, "write_payload", new_profile->write_payload) ) {
            std::string wf;
            load_if_exists(cur_object, "write_format", wf);
            new_profile->write_format = ContentCaptureFormat(wf);

            new_profile->element_name() = name;
            db_prof_content[name] = new_profile;

            if(cur_object.exists("content_rules")) {
                load_db_prof_content_subrules(cur_object, new_profile.get());
            }

            load_db_prof_content_write_format(cur_object, new_profile.get());

            _dia("load_db_prof_content: '%s': ok", name.c_str());
        } else {
            _dia("load_db_prof_content: '%s': not ok", name.c_str());
            Log::get()->events().insert(ERR, "CONFIG: content_profile '%s': write_payload not specified", name.c_str());
            CfgFactory::LOAD_ERRORS = true;
        }

        load_if_exists(cur_object, "webhook_enable", new_profile->webhook_enable);
        load_if_exists(cur_object, "webhook_lock_traffic", new_profile->webhook_lock_traffic);
    }

    return num;
}

int CfgFactory::load_db_tls_ca() {
    return 0;
}

int CfgFactory::load_db_prof_tls () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("load_db_prof_tls: start");
    
    if(cfgapi.getRoot().exists("tls_profiles")) {

        num = cfgapi.getRoot()["tls_profiles"].getLength();
        _dia("load_db_prof_tls: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["tls_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            Setting& cur_object = curr_set[i];


            if (  ! cur_object.getName() ) {
                _dia("load_db_prof_tls: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }

            auto new_profile = std::make_shared<ProfileTls>();

            _dia("load_db_prof_tls: processing '%s'", name.c_str());
            
            if( load_if_exists(cur_object, "inspect", new_profile->inspect) ) {

                new_profile->element_name() = name;
                load_if_exists(cur_object, "no_fallback_bypass", new_profile->no_fallback_bypass);

                load_if_exists(cur_object, "allow_untrusted_issuers", new_profile->allow_untrusted_issuers);
                load_if_exists(cur_object, "allow_invalid_certs", new_profile->allow_invalid_certs);
                load_if_exists(cur_object, "allow_self_signed", new_profile->allow_self_signed);
                load_if_exists(cur_object, "use_pfs", new_profile->use_pfs);
                load_if_exists(cur_object, "left_use_pfs", new_profile->left_use_pfs);
                load_if_exists(cur_object, "right_use_pfs", new_profile->right_use_pfs);
                load_if_exists(cur_object, "left_disable_reuse", new_profile->left_disable_reuse);
                load_if_exists(cur_object, "right_disable_reuse", new_profile->right_disable_reuse);

                load_if_exists(cur_object, "ocsp_mode", new_profile->ocsp_mode);
                load_if_exists(cur_object, "ocsp_stapling", new_profile->ocsp_stapling);
                load_if_exists(cur_object, "ocsp_stapling_mode", new_profile->ocsp_stapling_mode);
                load_if_exists(cur_object, "ct_enable", new_profile->opt_ct_enable);
                load_if_exists(cur_object, "alpn_block", new_profile->opt_alpn_block);
                load_if_exists(cur_object, "failed_certcheck_replacement", new_profile->failed_certcheck_replacement);
                load_if_exists(cur_object, "failed_certcheck_override", new_profile->failed_certcheck_override);
                load_if_exists(cur_object, "failed_certcheck_override_timeout", new_profile->failed_certcheck_override_timeout);
                load_if_exists(cur_object, "failed_certcheck_override_timeout_type", new_profile->failed_certcheck_override_timeout_type);
                load_if_exists(cur_object, "sni_based_cert", new_profile->mitm_cert_sni_search);
                load_if_exists(cur_object, "ip_based_cert", new_profile->mitm_cert_ip_search);
                load_if_exists(cur_object, "only_custom_certs", new_profile->mitm_cert_searched_only);

                if(cur_object.exists("sni_filter_bypass")) {
                        Setting& sni_filter = cur_object["sni_filter_bypass"];
                        
                        //init only when there is something
                        int sni_filter_len = sni_filter.getLength();
                        if(sni_filter_len > 0) {
                                new_profile->sni_filter_bypass = std::make_shared<std::vector<std::string>>();
                                new_profile->sni_filter_bypass_addrobj = std::make_shared<std::vector<FqdnAddress>>();

                                for(int j = 0; j < sni_filter_len; ++j) {
                                    const char* elem = sni_filter[j];
                                    new_profile->sni_filter_bypass->push_back(elem);
                                    new_profile->sni_filter_bypass_addrobj->emplace_back(elem);
                                }
                        }
                }
                

                if(cur_object.exists("redirect_warning_ports")) {
                        Setting& rwp = cur_object["redirect_warning_ports"];
                        
                        //init only when there is something
                        int rwp_len = rwp.getLength();
                        if(rwp_len > 0) {
                                new_profile->redirect_warning_ports.ptr(new std::set<int>);
                                for(int j = 0; j < rwp_len; ++j) {
                                    int elem = rwp[j];
                                    new_profile->redirect_warning_ports.ptr()->insert(elem);
                                }
                        }
                }
                load_if_exists(cur_object, "sslkeylog", new_profile->sslkeylog);
                
                db_prof_tls[name] = new_profile;

                _dia("load_db_prof_tls: '%s': ok", name.c_str());
            } else {
                _dia("load_db_prof_tls: '%s': not ok", name.c_str());
            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_prof_alg_dns () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    int num = 0;
    _dia("cfgapi_load_obj_alg_dns_profile: start");
    if(cfgapi.getRoot().exists("alg_dns_profiles")) {
        num = cfgapi.getRoot()["alg_dns_profiles"].getLength();
        _dia("cfgapi_load_obj_alg_dns_profile: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["alg_dns_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            auto new_prof = std::make_unique<ProfileAlgDns>();
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_obj_alg_dns_profile: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _dia("cfgapi_load_obj_alg_dns_profile: processing '%s'", name.c_str());

            new_prof->element_name() = name;
            load_if_exists(cur_object, "match_request_id", new_prof->match_request_id);
            load_if_exists(cur_object, "randomize_id", new_prof->randomize_id);
            load_if_exists(cur_object, "cached_responses", new_prof->cached_responses);
            
            db_prof_alg_dns[name] = std::shared_ptr<ProfileAlgDns>(std::move(new_prof));
        }
    }
    
    return num;
}

[[maybe_unused]]
int CfgFactory::load_db_prof_script () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    int num = 0;
    _dia("load_db_prof_script: start");
    if(cfgapi.getRoot().exists("script_profiles")) {
        num = cfgapi.getRoot()["script_profiles"].getLength();
        _dia("load_db_prof_script: found %d objects", num);

        Setting& curr_set = cfgapi.getRoot()["script_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            auto new_prof = std::make_unique<ProfileScript>();

            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("load_db_prof_script: unnamed object index %d: not ok", i);

                continue;
            }

            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _dia("load_db_prof_script: processing '%s'", name.c_str());

            new_prof->element_name() = name;
            load_if_exists(cur_object, "type", new_prof->script_type);
            load_if_exists(cur_object, "script-file", new_prof->module_path);

            db_prof_script[name] = std::shared_ptr<ProfileScript>(std::move(new_prof));
        }
    }

    return num;
}


int CfgFactory::load_db_prof_auth () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("load_db_prof_auth: start");

    _dia("load_db_prof_auth: portal settings");
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "address", AuthFactory::get().options.portal_address);

    load_if_exists<std::string>(cfgapi.getRoot()["settings"]["auth_portal"], "address6", AuthFactory::get().options.portal_address6);
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "http_port", AuthFactory::get().options.portal_port_http);
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "https_port", AuthFactory::get().options.portal_port_https);

    _dia("load_db_prof_auth: profiles");
    if(cfgapi.getRoot().exists("auth_profiles")) {

        num = cfgapi.getRoot()["auth_profiles"].getLength();
        _dia("load_db_prof_auth: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["auth_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            auto* a = new ProfileAuth;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("load_db_prof_auth: unnamed object index %d: not ok", i);
                delete a; // coverity: 1408003
                continue;
            }
            
            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _deb("load_db_prof_auth: processing '%s'", name.c_str());

            a->element_name() = name;
            load_if_exists(cur_object, "authenticate", a->authenticate);
            load_if_exists(cur_object, "resolve", a->resolve);
            
            if(cur_object.exists("identities")) {
                _dia("load_db_prof_auth: profiles: subpolicies exists");
                int sub_pol_num = cur_object["identities"].getLength();
                _dia("load_db_prof_auth: profiles: %d subpolicies detected", sub_pol_num);
                for (int j = 0; j < sub_pol_num; j++) {
                    Setting& cur_subpol = cur_object["identities"][j];
                    
                    auto n_subpol = std::make_shared<ProfileSubAuth>();

                    if (  ! cur_subpol.getName() ) {
                        _dia("load_db_prof_auth: profiles: unnamed object index %d: not ok", j);
                        continue;
                    }

                    std::string sub_name = cur_subpol.getName();
                    if(sub_name.find("__") == 0) {
                        // don't process reserved names
                        continue;
                    }

                    n_subpol->element_name() = sub_name;

                    std::string name_content;
                    std::string name_detection;
                    std::string name_tls;
                    std::string name_auth;
                    std::string name_alg_dns;
                    
                    if(load_if_exists(cur_subpol, "detection_profile", name_detection)) {
                        auto prf  = lookup_prof_detection(name_detection.c_str());
                        if(prf) {
                            _dia("load_db_prof_auth[sub-profile:%s]: detect profile %s", n_subpol->element_name().c_str(), name_detection.c_str());
                            n_subpol->profile_detection = prf;
                        } else {
                            _err("load_db_prof_auth[sub-profile:%s]: detect profile %s cannot be loaded",
                                 n_subpol->element_name().c_str(), name_detection.c_str());
                            Log::get()->events().insert(WAR, "CONFIG: policy[%d/%s]: detect profile '%s' cannot be loaded",
                                                                  i,n_subpol->element_name().c_str(), name_detection.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
                    }
                    
                    if(load_if_exists(cur_subpol, "content_profile", name_content)) {
                        auto prf  = lookup_prof_content(name_content.c_str());
                        if(prf) {
                            _dia("load_db_prof_auth[sub-profile:%s]: content profile %s", n_subpol->element_name().c_str(), name_content.c_str());
                            n_subpol->profile_content = prf;
                        } else {
                            _err("load_db_prof_auth[sub-profile:%s]: content profile %s cannot be loaded",
                                 n_subpol->element_name().c_str(), name_content.c_str());
                            Log::get()->events().insert(WAR, "CONFIG: policy[%d/%s]: content profile '%s' cannot be loaded",
                                                        i,n_subpol->element_name().c_str(), name_content.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
                    }                
                    if(load_if_exists(cur_subpol, "tls_profile", name_tls)) {
                        auto tls  = lookup_prof_tls(name_tls.c_str());
                        if(tls) {
                            _dia("load_db_prof_auth[sub-profile:%s]: tls profile %s", n_subpol->element_name().c_str(), name_tls.c_str());
                            n_subpol->profile_tls = std::shared_ptr<ProfileTls>(tls);
                        } else {
                            _err("load_db_prof_auth[sub-profile:%s]: tls profile %s cannot be loaded",
                                 n_subpol->element_name().c_str(), name_tls.c_str());
                            Log::get()->events().insert(WAR, "CONFIG: policy[%d/%s]: tls profile '%s' cannot be loaded",
                                                        i,n_subpol->element_name().c_str(), name_tls.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
                    }         

                    // we don't need auth profile in auth sub-profile
                    
                    if(load_if_exists(cur_subpol, "alg_dns_profile", name_alg_dns)) {
                        auto dns  = lookup_prof_alg_dns(name_alg_dns.c_str());
                        if(dns) {
                            _dia("load_db_prof_auth[sub-profile:%s]: DNS alg profile %s", n_subpol->element_name().c_str(), name_alg_dns.c_str());
                            n_subpol->profile_alg_dns = dns;
                        } else {
                            _err("load_db_prof_auth[sub-profile:%s]: DNS alg %s cannot be loaded",
                                 n_subpol->element_name().c_str(), name_alg_dns.c_str());
                            Log::get()->events().insert(WAR, "CONFIG: policy[%d/%s]: dns profile '%s' cannot be loaded",
                                                        i,n_subpol->element_name().c_str(), name_alg_dns.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
                    }                    

                    
                    a->sub_policies.push_back(n_subpol);
                    _dia("load_db_prof_auth: profiles: %d:%s", j, n_subpol->element_name().c_str());
                }
            }
            db_prof_auth[name] = std::shared_ptr<ProfileAuth>(a);

            _dia("load_db_prof_auth: '%s': ok", name.c_str());
        }
    }
    
    return num;
}




size_t CfgFactory::cleanup_db_address () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    auto r = db_address.size();
    db_address.clear();
    
    _deb("cleanup_db_address: %d objects freed", r);
    return r;
}

size_t CfgFactory::cleanup_db_policy () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    
    auto r = db_policy_list.size();
    db_policy_list.clear();
    db_policy.clear();
    
    _deb("cleanup_db_policy: %d objects freed", r);
    return r;
}

size_t CfgFactory::cleanup_db_port () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_port.size();
    db_port.clear();
    
    return r;
}

size_t CfgFactory::cleanup_db_proto () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_proto.size();
    db_proto.clear();
    
    return r;
}


size_t CfgFactory::cleanup_db_prof_content () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_content.size();
    db_prof_content.clear();
    
    return r;
}
size_t CfgFactory::cleanup_db_prof_detection () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_detection.size();
    db_prof_detection.clear();
    
    return r;
}

size_t CfgFactory::cleanup_db_tls_ca () {
    std::scoped_lock<std::recursive_mutex> l(lock_);
    return 0;
}

size_t CfgFactory::cleanup_db_prof_tls () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_tls.size();
    db_prof_tls.clear();
    
    return r;
}

size_t CfgFactory::cleanup_db_prof_alg_dns () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_alg_dns.size();
    db_prof_alg_dns.clear();
    
    return r;
}

size_t CfgFactory::cleanup_db_prof_script () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_script.size();
    if(r > 0)
        db_prof_script.clear();

    return r;
}


size_t CfgFactory::cleanup_db_prof_auth () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_prof_auth.size();
    db_prof_auth.clear();
    
    return r;
}


bool CfgFactory::prof_content_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileContent> &pc) {

    auto const& log = log::policy();

    auto* mitm_proxy = dynamic_cast<MitmProxy*>(new_proxy);

    bool ret = true;
    bool cfg_wrt;

    if(mitm_proxy != nullptr) {
        if(pc != nullptr) {
            const char* pc_name = pc->element_name().c_str();
            _dia("policy_apply: policy content profile[%s]: write payload: %d", pc_name, pc->write_payload);

            mitm_proxy->writer_opts()->write_payload = pc->write_payload;
            mitm_proxy->writer_opts()->webhook_enable = pc->webhook_enable;
            mitm_proxy->writer_opts()->webhook_lock_traffic = pc->webhook_lock_traffic;

            if( ! pc->content_rules.empty() ) {
                _dia("policy_apply: policy content profile[%s]: applying content rules, size %d", pc_name, pc->content_rules.size());
                mitm_proxy->init_content_replace();
                mitm_proxy->content_replace(pc->content_rules);
            }
        }
        else if(load_if_exists(cfgapi.getRoot()["settings"], "default_write_payload", cfg_wrt)) {
            _dia("policy_apply: global content profile: %d", cfg_wrt);
            mitm_proxy->writer_opts()->write_payload = cfg_wrt;
        }
        
        if(mitm_proxy->writer_opts()->write_payload) {
            mitm_proxy->toggle_tlog();

            if(mitm_proxy->tlog())
                mitm_proxy->tlog()->write_left("Connection start\n");
        }
    } else {
        _war("policy_apply: cannot apply content profile: cast to MitmProxy failed.");
        ret = false;
    } 
    
    return ret;
}


bool CfgFactory::prof_detect_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileDetection> &pd) {

    auto* mitm_originator = dynamic_cast<MitmHostCX*>(originator);
    auto const& log = log::policy();

    const char* pd_name = "none";
    bool ret = true;
    
    // we scan connection on client's side
    if(mitm_originator != nullptr) {
        mitm_originator->mode(AppHostCX::mode_t::NONE);
        if(pd != nullptr)  {
            pd_name = pd->element_name().c_str();
            _dia("policy_apply[%s]: policy detection profile: mode: %d", pd_name, pd->mode);
            mitm_originator->mode(static_cast<AppHostCX::mode_t>(pd->mode));
            mitm_originator->opt_engines_enabled = pd->engines_enabled;
            mitm_originator->opt_kb_enabled = pd->kb_enabled;
        }
    } else {
        _war("policy_apply: cannot apply detection profile: cast to AppHostCX failed.");
        ret = false;
    }    
    
    return ret;
}


std::optional<std::vector<std::string>> CfgFactory::find_bypass_domain_hosts(std::string const& filter_element, bool wildcards_only)  {
    std::vector<std::string> to_match;
    {
        auto dd_ = std::scoped_lock(DNS::get_domain_lock());

        auto wildcard_element = filter_element;
        bool wildcard_planted = false;
        if(auto wlc_i = filter_element.find("*."); wlc_i == 0) {
            _dia("found wildcard SNI bypass element");
            wildcard_element.replace(0, 2, "");
            wildcard_planted = true;
        }

        // do not try to find subdomains based on filter-element string
        if(not wildcard_planted and wildcards_only) return std::nullopt;

        auto subdomain_cache = DNS::get_domain_cache().get(wildcard_element);
        if (subdomain_cache != nullptr) {
            for (auto const &subdomain: subdomain_cache->cache()) {

                std::vector<std::string> prefix_n_domainname = string_split(subdomain.first,
                                                                            ':');
                if (prefix_n_domainname.size() < 2)
                    continue; // continue if we can't strip A: or AAAA:

                to_match.emplace_back(prefix_n_domainname.at(1) + "." + wildcard_element);
            }
        }
    }

    return to_match.empty() ? std::nullopt : std::make_optional(to_match);
};

bool CfgFactory::prof_tls_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileTls> &ps) {

    auto const& log = log::policy();

    if(not ps) {
        _err("CfgFactory::prof_tls_apply[%s]: profile is null", new_proxy->to_string(iINF).c_str());
        return false;
    }

    bool tls_applied = false;

    if(not new_proxy or not originator) {
        _err("CfgFactory::prof_tls_apply[%s]: proxy or originator is null", new_proxy->to_string(iINF).c_str());
        return false;
    }

    if( not policy_apply_tls(ps, originator->com())) {
        _err("CfgFactory::prof_tls_apply[%s]: cannot apply on originator cx", new_proxy->to_string(iINF).c_str());
        return false;
    }



    _dia("CfgFactory::prof_tls_apply[%s]: profile %s, originator %s", new_proxy->to_string(iINF).c_str(), ps->element_name().c_str(), originator->full_name('L').c_str());

    for( auto* cx: new_proxy->rs()) {
        baseCom* xcom = cx->com();
        _dia("CfgFactory::prof_tls_apply[%s]: profile %s, target %s", new_proxy->to_string(iINF).c_str(), ps->element_name().c_str(), cx->full_name('R').c_str());

        tls_applied = policy_apply_tls(ps, xcom);
        if(!tls_applied) {
            _err("%s: cannot apply TLS profile to target connection %s", new_proxy->c_type(), cx->c_type());
            tls_applied = false;
            break;
        }

        //applying bypass based on DNS cache

        auto* sslcom = dynamic_cast<SSLCom*>(xcom);
        if(sslcom && ps->sni_filter_bypass) {
            if( ( ! ps->sni_filter_bypass->empty() ) && ps->sni_filter_use_dns_cache) {

                bool interrupt = false;
                for(FqdnAddress& sni_fqdn: *ps->sni_filter_bypass_addrobj) {

                    auto target = CidrAddress(xcom->owner_cx()->host());

                    if(sni_fqdn.match(target.cidr())) {
                        if(sslcom->bypass_me_and_peer()) {
                            _inf("Connection %s bypassed: IP in DNS cache matching TLS bypass list (%s).", originator->full_name('L').c_str(), sni_fqdn.fqdn().c_str());
                            interrupt = true;
                            break;
                        } else {
                            _war("Connection %s: cannot be bypassed.", originator->full_name('L').c_str());
                        }
                    }
                    else if (ps->sni_filter_use_dns_domain_tree) {

                        // don't look for subdomains of current fqdn
                        auto to_match = find_bypass_domain_hosts(sni_fqdn.fqdn(), true);
                        if(not to_match) continue;

                        for(auto const& to_match_entry: to_match.value()) {
                            FqdnAddress ff(to_match_entry);
                            _deb("Connection %s: subdomain check: test if %s matches %s", originator->full_name('L').c_str(), ff.str().c_str(), xcom->owner_cx()->host().c_str());

                            // ff.match locks DNS cache
                            if(ff.match(target.cidr())) {
                                if(sslcom->bypass_me_and_peer()) {
                                    _inf("Connection %s bypassed: IP in DNS sub-domain cache matching TLS bypass list (%s).", originator->full_name('L').c_str(), sni_fqdn.fqdn().c_str());
                                } else {
                                    _war("Connection %s: cannot be bypassed.", originator->full_name('L').c_str());
                                }
                                interrupt = true; //exit also from main loop
                                break;
                            }
                        }
                    }
                }

                if(interrupt)
                    break;

            }
        }

    }

    
    return tls_applied;
}

bool CfgFactory::prof_alg_dns_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileAlgDns> &p_alg_dns) {

    auto const& log = log::policy();

    auto* mitm_originator = dynamic_cast<AppHostCX*>(originator);
    auto* mh = dynamic_cast<MitmHostCX*>(mitm_originator);

    bool ret = false;
    
    if(mh != nullptr) {

        if(p_alg_dns != nullptr) {
            if(DNS_Inspector::dns_prefilter(mh)) {
                auto* n = new DNS_Inspector();

                _dia("policy_apply: policy dns profile[%s] for %s", p_alg_dns->element_name().c_str(), mitm_originator->full_name('L').c_str());
                n->opt_match_id = p_alg_dns->match_request_id;
                n->opt_randomize_id = p_alg_dns->randomize_id;
                n->opt_cached_responses = p_alg_dns->cached_responses;
                mh->inspectors_.emplace_back(n);
                ret = true;
            }
        }
        
    } else {
        _not("CfgFactory::prof_alg_dns_apply: connection %s is not MitmHost", originator->full_name('L').c_str());
    }    
    
    return ret;
}


bool CfgFactory::prof_script_apply (baseHostCX *originator, baseProxy *new_proxy, std::shared_ptr<ProfileScript> const& p_script) {

    auto const& log = log::policy();

    auto* mitm_originator = dynamic_cast<AppHostCX*>(originator);
    auto* mh = dynamic_cast<MitmHostCX*>(mitm_originator);

    bool ret = false;

    if(mh != nullptr) {

        if(p_script) {

            _dia("policy_apply: policy script profile[%s] for %s", p_script->element_name().c_str(), mitm_originator->full_name('L').c_str());

            if(p_script->script_type == ProfileScript::ST_PYTHON) {
                #ifdef USE_PYTHON
                auto new_prof = std::make_unique<PythonInspector>();
                if(new_prof->l4_prefilter(mh)) {
                    mh->inspectors_.push_back(std::move(new_prof));
                    ret = true;
                }
                #else
                _err("CfgFactory::prof_script_apply: python scripting not supported by this build");
                #endif
            }
            else if(p_script->script_type == ProfileScript::ST_GOLANG) {
                _err("CfgFactory::prof_script_apply: golang scripting not yet implemented");
            }
            else
            {
                _err("CfgFactory::prof_script_apply: unknown script type");
            }
        }

    } else {
        _not("CfgFactory::prof_script_apply: connection %s is not MitmHost", originator->full_name('L').c_str());
    }

    return ret;
}

void CfgFactory::policy_apply_features(std::shared_ptr<PolicyRule> const & policy_rule, MitmProxy *mitm_proxy) {

    // apply feature tags
    if(policy_rule and not policy_rule->features.empty()) {
        FilterProxy* sink_filter = nullptr;
        FilterProxy* statistics_filter = nullptr;
        FilterProxy* access_filter = nullptr;

        for(auto const& it: policy_rule->features) {
            if(not sink_filter) {
                if (it->value() == "sink-all")  sink_filter = new SinkholeFilter(mitm_proxy, true, true);
                else if (it->value() == "sink-left") sink_filter = new SinkholeFilter(mitm_proxy, true, false);
                else if (it->value() == "sink-right") sink_filter = new SinkholeFilter(mitm_proxy, false, true);
            }

            if(not statistics_filter) {
                if (it->value() == "statistics") {
                    statistics_filter = new StatsFilter(mitm_proxy);

                }
            }

            if(not access_filter) {
                if (it->value() == "access-request") {
                    access_filter = new AccessFilter(mitm_proxy);
                }
            }
        }

        if(access_filter) {
            _dia("policy_apply_features: added access_filter");
            mitm_proxy->add_filter("access-request", access_filter);
        }
        if(statistics_filter) {
            _dia("policy_apply_features: added statistics");
            mitm_proxy->add_filter("statistics", statistics_filter);
        }
        if(sink_filter) {
            _dia("policy_apply_features: added sinkhole");
            mitm_proxy->add_filter("sinkhole", sink_filter);
        }

    }

}

int CfgFactory::policy_apply (baseHostCX *originator, baseProxy *proxy, int matched_policy) {

    auto const& log = log::policy();

    auto lc_ = std::scoped_lock(lock_);
    
    int policy_num = matched_policy;
    if(policy_num < 1) {
        policy_num = policy_match(proxy);
    }
    if(auto verdict = policy_action(policy_num); verdict == PolicyRule::POLICY_ACTION_PASS) {
        auto rule = policy_rule(policy_num);

        auto pc = policy_prof_content(policy_num);
        auto pd = policy_prof_detection(policy_num);
        auto pt = policy_prof_tls(policy_num);
        auto pa = policy_prof_auth(policy_num);
        auto p_alg_dns = policy_prof_alg_dns(policy_num);


        const char *pc_name = "none";
        const char *pd_name = "none";
        const char *pt_name = "none";
        const char *pa_name = "none";

        //Algs will be list of single letter abbreviations
        // DNS alg: D
        std::string algs_name;

        /* Processing content profile */
        if (pc) {
            if (prof_content_apply(originator, proxy, pc)) {
                pc_name = pc->element_name().c_str();
            }
        }
        
        
        /* Processing detection profile */
        if (pd and prof_detect_apply(originator, proxy, pd)) {
            pd_name = pd->element_name().c_str();
        }
        
        /* Processing TLS profile*/
        if (pt and prof_tls_apply(originator, proxy, pt)) {
            pt_name = pt->element_name().c_str();
        }
        
        /* Processing ALG : DNS*/
        if (p_alg_dns and prof_alg_dns_apply(originator, proxy, p_alg_dns)) {
            algs_name += p_alg_dns->element_name();
        }

        auto* mitm_proxy = dynamic_cast<MitmProxy*>(proxy);
        if(mitm_proxy) {

            /* Processing Auth profile */
            if(pa) {
                // auth is applied on proxy
                mitm_proxy->auth_opts.authenticate = pa->authenticate;
                mitm_proxy->auth_opts.resolve = pa->resolve;

                pa_name = pa->element_name().c_str();
            }

            /* Processing Features */
            policy_apply_features(rule, mitm_proxy);
        }
        
        // ALGS can operate only on MitmHostCX classes

        
        _inf("Connection %s accepted: policy=%d cont=%s det=%s tls=%s auth=%s algs=%s", originator->full_name('L').c_str(), policy_num, pc_name, pd_name, pt_name, pa_name, algs_name.c_str());

    } else {
        _inf("Connection %s denied: policy=%d", originator->full_name('L').c_str(), policy_num);
    }
    
    return policy_num;
}


void CfgFactory::gre_export_apply(traflog::PcapLog* pcaplog) {

    auto const& cfg = CfgFactory::get();

    if(cfg->capture_remote.enabled) {
        if(not cfg->capture_remote.tun_dst.empty()) {
            auto c = CidrAddress(cfg->capture_remote.tun_dst);

            auto ip = c.ip();
            auto fam = c.cidr()->proto;

            auto exp = std::make_shared<traflog::GreExporter>(fam, ip);
            pcaplog->ip_packet_hook = exp;
            if(cfg->capture_remote.tun_ttl > 0)
                exp->ttl(cfg->capture_remote.tun_ttl);

        } else {
            pcaplog->ip_packet_hook.reset();
        }
    } else {
        pcaplog->ip_packet_hook.reset();
    }
};

/// @brief loads signature definitions from config object and places then into a signature tree
/// @param cfg 'cfg' Config object
/// @param name 'name' config element name (full path)
/// @param signature_tree 'signature_tree' where to place created signature
/// @param if non-negative, overrides signature group index, otherwise gets group name via group index lookup
int CfgFactory::load_signatures(libconfig::Config &cfg, const char *name, SignatureTree &signature_tree,
                                 int preferred_index) {

    using namespace libconfig;

    const Setting& root = cfg.getRoot();
    const Setting& cfg_signatures = root[name];
    int sigs_len = cfg_signatures.getLength();

    _dia("Loading %s: %d", name, sigs_len);
    for ( int i = 0 ; i < sigs_len; i++) {
        auto newsig = std::make_shared<MyDuplexFlowMatch>();


        const Setting& signature = cfg_signatures[i];
        load_if_exists(signature, "name", newsig->name());
        load_if_exists(signature, "side", newsig->sig_side);
        load_if_exists(signature, "cat", newsig->sig_category);
        load_if_exists(signature, "severity", newsig->sig_severity);
        load_if_exists(signature, "group", newsig->sig_group);
        load_if_exists(signature, "enables", newsig->sig_enables);
        load_if_exists(signature, "engine", newsig->sig_engine);

        const Setting& signature_flow = cfg_signatures[i]["flow"];
        int flow_count = signature_flow.getLength();

        _dia("Loading signature '%s' with %d flow matches",newsig->name().c_str(),flow_count);


        for ( int j = 0; j < flow_count; j++ ) {

            std::string side;
            std::string type;
            std::string sigtext;
            int bytes_start;
            int bytes_max;

            if(!( load_if_exists(signature_flow[j], "side", side)
                  && load_if_exists(signature_flow[j], "type", type)
                  && load_if_exists(signature_flow[j], "signature", sigtext)
                  && load_if_exists(signature_flow[j], "bytes_start", bytes_start)
                  && load_if_exists(signature_flow[j], "bytes_max", bytes_max))) {

                _war("Starttls signature %s properties failed to load: index %d",newsig->name().c_str(), i);
                Log::get()->events().insert(WAR,"CONFIG: signature[%s/%s/%d]: missing mandatory settings", name, newsig->name().c_str(), j);
                CfgFactory::LOAD_ERRORS = true;


                continue;
            }

            if( type == "regex") {
                _deb(" [%d]: new regex flow match",j);
                try {
                    newsig->add(side[0], new regexMatch(sigtext, bytes_start, bytes_max));
                } catch(std::regex_error const& e) {

                    _err("Starttls signature %s regex failed to load: index %d, load aborted: %s", newsig->name().c_str() , i, e.what());
                    Log::get()->events().insert(WAR,"CONFIG: signature[%s/%s/%d]: regex error: '%s'", name, newsig->name().c_str(), j, e.what());
                    CfgFactory::LOAD_ERRORS = true;


                    newsig = nullptr;
                    break;
                }
            } else
            if ( type == "simple") {
                _deb(" [%d]: new simple flow match", j);
                newsig->add(side[0],new simpleMatch(sigtext,bytes_start,bytes_max));
            } else {
                Log::get()->events().insert(WAR,"CONFIG: signature[%s/%s/%d]: unknown type '%s'", name, newsig->name().c_str(), j, type.c_str());
                CfgFactory::LOAD_ERRORS = true;
            }
        }

        // load if not set to null due to loading error
        if(newsig) {
            // emplace also dummy flowMatchState which won't be used. Little overhead for good abstraction.
            if(preferred_index >= 0) {
                // starttls signatures
                signature_tree.sensors_[preferred_index]->emplace_back(flowMatchState(), newsig);
            }
            else {
                if(newsig->sig_group.empty() or newsig->sig_group == "base") {
                    // element 1 is base signatures
                    signature_tree.sensors_[1]->emplace_back(flowMatchState(), newsig);
                }
                else {
                    signature_tree.signature_add(newsig, newsig->sig_group.c_str(), false);
                }
            }
        }
    }

    return sigs_len;
}



bool CfgFactory::apply_config_change(std::string_view section) {
    bool ret = false;

    if( 0 == section.find("settings") ) {
        ret = CfgFactory::get()->load_settings();
    } else
    if( 0 == section.find("captures") ) {
        ret = CfgFactory::get()->load_captures();
    } else
#ifdef USE_EXPERIMENT
        if( 0 == section.find("experiment") ) {
        ret = CfgFactory::get()->load_experiment();
    } else
#endif
    if( 0 == section.find("debug") ) {
        ret = CfgFactory::get()->load_debug();
    } else
    if( 0 == section.find("policy") ) {

        CfgFactory::get()->cleanup_db_policy();
        ret = CfgFactory::get()->load_db_policy();
    } else
    if( 0 == section.find("port_objects") ) {

        CfgFactory::get()->cleanup_db_port();
        ret = CfgFactory::get()->load_db_port();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("proto_objects") ) {

        CfgFactory::get()->cleanup_db_proto();
        ret = CfgFactory::get()->load_db_proto();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("address_objects") ) {

        CfgFactory::get()->cleanup_db_address();
        ret = CfgFactory::get()->load_db_address();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("detection_profiles") ) {

        CfgFactory::get()->cleanup_db_prof_detection();
        ret = CfgFactory::get()->load_db_prof_detection();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("content_profiles") ) {

        CfgFactory::get()->cleanup_db_prof_content();
        ret = CfgFactory::get()->load_db_prof_content();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("tls_profiles") ) {

        CfgFactory::get()->cleanup_db_prof_tls();
        ret = CfgFactory::get()->load_db_prof_tls();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("alg_dns_profiles") ) {

        CfgFactory::get()->cleanup_db_prof_alg_dns();
        ret = CfgFactory::get()->load_db_prof_alg_dns();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    } else
    if( 0 == section.find("auth_profiles") ) {

        CfgFactory::get()->cleanup_db_prof_auth();
        ret = CfgFactory::get()->load_db_prof_auth();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    }
    else
    if( 0 == section.find("routing") ) {

        CfgFactory::get()->cleanup_db_routing();
        ret = CfgFactory::get()->load_db_routing();

        if(ret) {
            CfgFactory::get()->cleanup_db_policy();
            ret = CfgFactory::get()->load_db_policy();
        }
    }
    else
    if( 0 == section.find("starttls_signatures") or
        0 == section.find("detection_signatures") ) {

        CfgFactory::get()->load_signatures(CfgFactory::cfg_obj(), "starttls_signatures", SigFactory::get().signature_tree(),0);
        CfgFactory::get()->load_signatures(CfgFactory::cfg_obj(), "detection_signatures", SigFactory::get().signature_tree());

        CfgFactory::get()->cleanup_db_policy();
        ret = CfgFactory::get()->load_db_policy();
    }

    return ret;
}

bool CfgFactory::policy_apply_tls (int policy_num, baseCom *xcom) {
    auto pt = policy_prof_tls(policy_num);
    return policy_apply_tls(pt, xcom);
}

bool CfgFactory::should_redirect (const std::shared_ptr<ProfileTls> &pt, SSLCom *com) {

    auto const& log = log::policy();
    
    bool ret = false;
    
    _deb("should_redirect[%s]", com->hr().c_str());
    
    if(com && com->owner_cx()) {

        if(com->owner_cx()->port().empty()) {
            _deb("should_redirect[%s]: unknown cx port", com->hr().c_str());
            return false;
        }

        try {
            int num_port = std::stoi(com->owner_cx()->port());
            _deb("should_redirect[%s]: owner port %d", com->hr().c_str(), num_port);
            
            
            if(pt->redirect_warning_ports.ptr()) {
                // we have port redirection list (which ports should be redirected/replaced for cert issue warning)
                _deb("should_redirect[%s]: checking port list present", com->hr().c_str());
                
                auto it = pt->redirect_warning_ports.ptr()->find(num_port);
                
                if(it != pt->redirect_warning_ports.ptr()->end()) {
                    _dia("should_redirect[%s]: port %d allowed to be redirected if needed", com->hr().c_str(), num_port);
                    ret = true;
                }
            }
            else {
                // if we have list empty (uninitialized), we assume only 443 should be redirected
                if(num_port == 443) {
                    _deb("should_redirect[%s]: implicit 443 redirection allowed (no port list)", com->hr().c_str());
                    ret = true;
                }
            }
        }
        catch(std::invalid_argument const& e) {
            _err("should_redirect[%s]: %s", com->hr().c_str(), e.what());
        }
        catch(std::out_of_range const& e) {
            _err("should_redirect[%s]: %s", com->hr().c_str(), e.what());
        }
    }
    
    return ret;
}

bool CfgFactory::policy_apply_tls (const std::shared_ptr<ProfileTls> &pt, baseCom *xcom) {

    if(not pt or not xcom) {
        _err("CfgFactory::policy_apply_tls: null argument: profile %x, com %x", pt.get(), xcom);
        return false;
    }

    auto const& log = log::policy();

    bool tls_applied = false;     
    
    auto* sslcom = dynamic_cast<SSLCom*>(xcom);
    if(sslcom != nullptr) {
        sslcom->opt.bypass = !pt->inspect;
        if(sslcom->opt.bypass) {
            sslcom->verify_reset(SSLCom::verify_status_t::VRF_OK);
        }
        sslcom->opt.no_fallback_bypass = pt->no_fallback_bypass;

        sslcom->opt.cert.allow_unknown_issuer = pt->allow_untrusted_issuers;
        sslcom->opt.cert.allow_self_signed_chain = pt->allow_untrusted_issuers;
        sslcom->opt.cert.allow_not_valid = pt->allow_invalid_certs;
        sslcom->opt.cert.allow_self_signed = pt->allow_self_signed;

        sslcom->opt.cert.failed_check_replacement = pt->failed_certcheck_replacement;
        sslcom->opt.cert.failed_check_override = pt->failed_certcheck_override;
        sslcom->opt.cert.failed_check_override_timeout = pt->failed_certcheck_override_timeout;
        sslcom->opt.cert.failed_check_override_timeout_type = pt->failed_certcheck_override_timeout_type;
        sslcom->opt.cert.mitm_cert_sni_search = pt->mitm_cert_sni_search;
        sslcom->opt.cert.mitm_cert_ip_search = pt->mitm_cert_ip_search;
        sslcom->opt.cert.mitm_cert_searched_only = pt->mitm_cert_searched_only;

        auto* peer_sslcom = dynamic_cast<SSLCom*>(sslcom->peer());

        if( peer_sslcom &&
                pt->failed_certcheck_replacement &&
                should_redirect(pt, peer_sslcom)) {

            _deb("policy_apply_tls: applying profile, repl=%d, repl_ovrd=%d, repl_ovrd_tmo=%d, repl_ovrd_tmo_type=%d, sni_search=%d, ip_search=%d, custom_only=%d",
                 pt->failed_certcheck_replacement,
                 pt->failed_certcheck_override,
                 pt->failed_certcheck_override_timeout,
                 pt->failed_certcheck_override_timeout_type,
                 pt->mitm_cert_sni_search,
                 pt->mitm_cert_ip_search,
                 pt->mitm_cert_searched_only);

            peer_sslcom->opt.cert.failed_check_replacement = pt->failed_certcheck_replacement;
            peer_sslcom->opt.cert.failed_check_override = pt->failed_certcheck_override;
            peer_sslcom->opt.cert.failed_check_override_timeout = pt->failed_certcheck_override_timeout;
            peer_sslcom->opt.cert.failed_check_override_timeout_type = pt->failed_certcheck_override_timeout_type;
            peer_sslcom->opt.cert.mitm_cert_sni_search = pt->mitm_cert_sni_search;
            peer_sslcom->opt.cert.mitm_cert_ip_search = pt->mitm_cert_ip_search;
            peer_sslcom->opt.cert.mitm_cert_searched_only = pt->mitm_cert_searched_only;
        }

        // set accordingly if general "use_pfs" is specified, more concrete settings come later
        sslcom->opt.left.kex_dh = pt->use_pfs;
        sslcom->opt.right.kex_dh = pt->use_pfs;

        sslcom->opt.left.kex_dh = pt->left_use_pfs;
        sslcom->opt.right.kex_dh = pt->right_use_pfs;

        sslcom->opt.left.no_tickets = pt->left_disable_reuse;
        sslcom->opt.right.no_tickets = pt->right_disable_reuse;

        sslcom->opt.ocsp.mode = pt->ocsp_mode;
        sslcom->opt.ocsp.stapling_enabled = pt->ocsp_stapling;
        sslcom->opt.ocsp.stapling_mode = pt->ocsp_stapling_mode;

        // certificate transparency
        sslcom->opt.ct_enable = pt->opt_ct_enable;

        // alpn alpn
        sslcom->opt.alpn_block = pt->opt_alpn_block;

        if(pt->sni_filter_bypass and not pt->sni_filter_bypass->empty()) {
            sslcom->sni_filter_to_bypass() = pt->sni_filter_bypass;
        }

        sslcom->sslkeylog = pt->sslkeylog;

        tls_applied = true;
    } else {
        _deb("CfgFactory::policy_apply_tls[%s]: is not SSL", xcom->shortname().c_str());
        tls_applied = true; // report ok, we won't apply TLS profile but it's not an error
    }

    return tls_applied;
}


void CfgFactory::cleanup()
{
    cleanup_db_policy();
    cleanup_db_address();
    cleanup_db_port();
    cleanup_db_proto();
    cleanup_db_prof_content();
    cleanup_db_prof_detection();
    cleanup_db_prof_tls();
    cleanup_db_prof_auth();
    cleanup_db_prof_alg_dns();
    cleanup_db_prof_script();
}


void CfgFactory::log_version (bool warn_delay)
{
    _cri("Starting Smithproxy %s (socle %s)", SMITH_VERSION, SOCLE_VERSION);
    
    if(SOCLE_DEVEL || SMITH_DEVEL) {
        _war("");
        if(SOCLE_DEVEL) {
            _war("Socle library version %s (dev)", SOCLE_VERSION);
        }
#ifdef SOCLE_MEM_PROFILE
        _war("*** PERFORMANCE: Socle library has extra memory profiling enabled! ***");
#endif
        if(SMITH_DEVEL) {
            _war("Smithproxy version %s (dev)", SMITH_VERSION);
        }        
        _war("");
        
        if(warn_delay) {
            _war("  ... start will continue in 3 sec.");
            sleep(3);
        }
    }
}

int CfgFactoryBase::apply_tenant_index(std::string& what, unsigned int const& idx) const {
    _deb("apply_index: what=%s idx=%d", what.c_str(), idx);
    int port = std::stoi(what);
    what = std::to_string(port + idx);

    return 0;
}


bool CfgFactory::apply_tenant_config () {
    int ret = 0;

    if(not tenant_name.empty()) {
        ret += apply_tenant_index(listen_tcp_port, tenant_index);
        ret += apply_tenant_index(listen_tls_port, tenant_index);
        ret += apply_tenant_index(listen_dtls_port, tenant_index);
        ret += apply_tenant_index(listen_udp_port, tenant_index);
        ret += apply_tenant_index(listen_socks_port, tenant_index);
        ret += apply_tenant_index(AuthFactory::get().options.portal_port_http, tenant_index);
        ret += apply_tenant_index(AuthFactory::get().options.portal_port_https, tenant_index);

        CfgFactory::get()->cli_port += tenant_index;
    }

    return (ret == 0);
}


bool CfgFactory::new_address_object(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);
        item.add("type", Setting::TypeString) = "cidr";  // cidr
        item.add("value", Setting::TypeString) = "0.0.0.0/32";
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s.%s: %s", ex.c_str(), name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_address_objects(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& address_objects = ex.getRoot().add("address_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_address) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<CfgAddress>(it.second);
        if(! obj) continue;

        Setting& item = address_objects.add(name, Setting::TypeGroup);

        if(obj->value()->c_type() == std::string("FqdnAddress")) {
            Setting &s_type = item.add("type", Setting::TypeString);
            Setting &s_fqdn = item.add("value", Setting::TypeString);

            s_type = "fqdn";
            auto fqdn_ptr = std::dynamic_pointer_cast<FqdnAddress>(obj->value());
            if(fqdn_ptr) {
                s_fqdn = fqdn_ptr->fqdn();
            }

            n_saved++;
        }
        else if(obj->value()->c_type() == std::string("CidrAddress")) {
            Setting &s_type = item.add("type", Setting::TypeString);
            Setting &s_cidr = item.add("value", Setting::TypeString);

            s_type = "cidr";

            auto cidr_ptr = std::dynamic_pointer_cast<CidrAddress>(obj->value());
            if(cidr_ptr) {
                const char* addr = cidr_to_str(cidr_ptr->cidr());
                s_cidr =  addr;
                delete[] addr;
            }

            n_saved++;
        }

    }

    return n_saved;
}


size_t CfgFactory::cleanup_db_routing () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto r = db_routing.size();
    db_routing.clear();

    return r;
}

int CfgFactory::load_db_routing () {

    std::scoped_lock<std::recursive_mutex> l(lock_);

    int loaded = 0;

    _dia("load_db_routing: start");

    if (cfgapi.getRoot().exists("routing")) {

        int num = cfgapi.getRoot()["routing"].getLength();
        _dia("load_db_routing: found %d objects", num);

        Setting &curr_set = cfgapi.getRoot()["routing"];

        for (int i = 0; i < num; i++) {
            std::string name;

            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("load_db_routing: unnamed object index %d: not ok", i);
                continue;
            }

            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }

            auto new_profile = std::make_shared<ProfileRouting>();
            new_profile->element_name() = name;

            if(cur_object.exists("dnat_address")) {
                auto& da = cur_object["dnat_address"];
                auto da_l = da.getLength();
                for (int j = 0; j < da_l; ++j) {
                    const char* address = da[j];
                    if(db_address.find(address) == db_address.end()) {
                        _dia("load_db_routing[%d]: unknown dnat address: '%s'", i, address);
                        Log::get()->events().insert(WAR,"CONFIG: routing_profile[%s]: dnat_address: address '%s' unknown", name.c_str(), address);
                        CfgFactory::LOAD_ERRORS = true;

                        continue;
                    }
                    new_profile->dnat_addresses.emplace_back(address);
                }
            }


            if(cur_object.exists("dnat_port")) {
                auto& dp = cur_object["dnat_port"];
                auto dp_l = dp.getLength();
                for (int j = 0; j < dp_l; ++j) {
                    const char* port = dp[j];
                    if(db_port.find(port) == db_port.end()) {
                        _dia("load_db_routing[%d]: unknown dnat port: '%s'", i, port);
                        Log::get()->events().insert(WAR,"CONFIG: routing_profile[%s]: dnat_port: port '%s' unknown", name.c_str(), port);
                        CfgFactory::LOAD_ERRORS = true;


                        continue;
                    }
                    new_profile->dnat_ports.emplace_back(port);
                }
            }

            std::string lb_meth;
            if(load_if_exists(cur_object, "dnat_lb_method", lb_meth)) {
                if(lb_meth == "sticky-l3") {
                    new_profile->dnat_lb_method = ProfileRouting::lb_method::LB_L3;
                }
                else if(lb_meth == "sticky-l4") {
                    new_profile->dnat_lb_method = ProfileRouting::lb_method::LB_L4;
                }
                else {
                    new_profile->dnat_lb_method = ProfileRouting::lb_method::LB_RR;
                }
            }

            db_routing[name] = new_profile;
            loaded++;
        }

    }

    return loaded;
}

int CfgFactory::save_routing(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("routing", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_routing) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileRouting>(it.second);
        if(!obj) continue;

        Setting& routing_item = objects.add(name, Setting::TypeGroup);

        auto& dnat_address = routing_item.add("dnat_address", Setting::TypeArray);
        for(auto const& dnat_it: obj->dnat_addresses)
            dnat_address.add(Setting::TypeString) = dnat_it;

        auto& dnat_port = routing_item.add("dnat_port", Setting::TypeArray);
        for(auto const& dnat_it: obj->dnat_ports)
            dnat_port.add(Setting::TypeString) = dnat_it;

        auto& lbm = routing_item.add("dnat_lb_method", Setting::TypeString);
        if(obj->dnat_lb_method == ProfileRouting::lb_method::LB_L3)
            lbm = "sticky-l3";
        else if(obj->dnat_lb_method == ProfileRouting::lb_method::LB_L4)
            lbm = "sticky-l4";
        else
            lbm = "round-robin";

        n_saved++;
    }

    return n_saved;
}


bool CfgFactory::new_routing(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);

        // to be added later
        // item.add("snat_address", Setting::TypeArray);
        // item.add("snat_port", Setting::TypeArray) ;

        item.add("dnat_address", Setting::TypeArray);
        item.add("dnat_port", Setting::TypeArray);

        item.add("dnat_lb_method", Setting::TypeString) = "round-robin";
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s.%s: %s", ex.c_str(), name.c_str(), e.what());
        return false;
    }

    return true;

}

bool CfgFactory::new_port_object(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);
        item.add("start", Setting::TypeInt) = 0;
        item.add("end", Setting::TypeInt) = 65535;
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s.%s: %s", ex.c_str(), name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_port_objects(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("port_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_port) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<CfgRange>(it.second);
        if(! obj) continue;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("start", Setting::TypeInt) = obj->value().first;
        item.add("end", Setting::TypeInt) = obj->value().second;

        n_saved++;
    }

    return n_saved;
}


bool CfgFactory::new_proto_object(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);
        item.add("id", Setting::TypeInt) = 0;
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_proto_objects(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("proto_objects", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_proto) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<CfgUint8>(it.second);
        if(!obj) continue;


        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("id", Setting::TypeInt) = obj->value();

        n_saved++;
    }

    return n_saved;
}


int CfgFactory::save_debug(Config& ex) const {

    if(!ex.exists("debug"))
        ex.getRoot().add("debug", Setting::TypeGroup);

    Setting& deb_objects = ex.getRoot()["debug"];

    deb_objects.add("log_data_crc", Setting::TypeBoolean) =  baseCom::debug_log_data_crc;
    deb_objects.add("log_sockets", Setting::TypeBoolean) = baseHostCX::socket_in_name;
    deb_objects.add("log_online_cx_name", Setting::TypeBoolean) = baseHostCX::online_name;
    deb_objects.add("log_srclines", Setting::TypeBoolean) = Log::get()->print_srcline();
    deb_objects.add("log_srclines_always", Setting::TypeBoolean) = Log::get()->print_srcline_always();


    Setting& deb_log_objects = deb_objects.add("log", Setting::TypeGroup);
    deb_log_objects.add("sslcom", Setting::TypeInt) = (int)SSLCom::log_level().level_ref();
    deb_log_objects.add("sslmitmcom", Setting::TypeInt) = (int)baseSSLMitmCom<DTLSCom>::log_level().level_ref();
    deb_log_objects.add("sslcertstore", Setting::TypeInt) = (int)SSLFactory::get_log().level()->level_ref();
    deb_log_objects.add("proxy", Setting::TypeInt) = (int)baseProxy::log_level().level_ref();
    deb_log_objects.add("epoll", Setting::TypeInt) = (int)epoll::log_level.level_ref();

    deb_log_objects.add("mtrace", Setting::TypeBoolean) = cfg_mtrace_enable;
    deb_log_objects.add("openssl_mem_dbg", Setting::TypeBoolean) = cfg_openssl_mem_dbg;

    deb_log_objects.add("alg_dns", Setting::TypeInt) = (int)DNS_Inspector::log_level().level_ref();
    deb_log_objects.add("pkt_dns", Setting::TypeInt) = (int)DNS_Packet::log_level().level_ref();


    return 0;
}


bool CfgFactory::new_detection_profile(Setting& ex, std::string const& name) const {

    try {
        Setting& item = ex.add(name, Setting::TypeGroup);
        item.add("mode", Setting::TypeInt) = 1; // PRE
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_detection_profiles(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("detection_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_prof_detection) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileDetection>(it.second);
        if(! obj) continue;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("mode", Setting::TypeInt) = obj->mode;
        item.add("engines_enabled", Setting::TypeBoolean) = obj->engines_enabled;
        item.add("kb_enabled", Setting::TypeBoolean) = obj->kb_enabled;

        n_saved++;
    }

    return n_saved;
}


bool CfgFactory::new_content_profile(Setting& ex, std::string const& name) const {

    try {
        Setting & item = ex.add(name, Setting::TypeGroup);
        item.add("write_payload", Setting::TypeBoolean) = false;
        item.add("content_rules", Setting::TypeList);
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }


    return true;
}

int CfgFactory::save_content_profiles(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("content_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_prof_content) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileContent>(it.second);
        if(! obj) continue;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("write_payload", Setting::TypeBoolean) = obj->write_payload;
        item.add("write_format", Setting::TypeString) = obj->write_format.to_str();

        item.add("webhook_enable", Setting::TypeBoolean) = obj->webhook_enable;
        item.add("webhook_lock_traffic", Setting::TypeBoolean) = obj->webhook_lock_traffic;

        if(! obj->content_rules.empty() ) {

            Setting& cr_rules = item.add("content_rules", Setting::TypeList);

            for(auto const& cr: obj->content_rules) {
                Setting& cr_rule = cr_rules.add(Setting::TypeGroup);
                cr_rule.add("match", Setting::TypeString) = cr.match;
                cr_rule.add("replace", Setting::TypeString) = cr.replace;
                cr_rule.add("replace_each_nth", Setting::TypeInt) = cr.replace_each_nth;
            }
        }

        n_saved++;
    }

    return n_saved;
}


bool CfgFactory::new_tls_ca(Setting& ex, std::string const& name) const {

    try {
        ex.add(name, Setting::TypeGroup);
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_tls_ca(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    [[maybe_unused]]
    Setting& objects = ex.getRoot().add("tls_ca", Setting::TypeGroup);

    int n_saved = 0;

//    for (auto it: cfgapi_obj_tls_ca) {
//        auto name = it.first;
//        auto obj = it.second;
//
//        Setting& item = objects.add(name, Setting::TypeGroup);
//        item.add("path", Setting::TypeString) = obj.path;
//
//        n_saved++;
//    }

    return n_saved;
}


bool CfgFactory::new_tls_profile(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);

        item.add("inspect", Setting::TypeBoolean) = false;
        item.add("no_fallback_bypass", Setting::TypeBoolean) = false;

        item.add("use_pfs", Setting::TypeBoolean) = true;
        item.add("left_use_pfs", Setting::TypeBoolean) = true;
        item.add("right_use_pfs", Setting::TypeBoolean) = true;

        item.add("allow_untrusted_issuers", Setting::TypeBoolean) = false;
        item.add("allow_invalid_certs", Setting::TypeBoolean) = false;
        item.add("allow_self_signed", Setting::TypeBoolean) = false;

        item.add("ocsp_mode", Setting::TypeInt) = 1;
        item.add("ocsp_stapling", Setting::TypeBoolean) = true;
        item.add("ocsp_stapling_mode", Setting::TypeInt) = 1;

        item.add("ct_enable", Setting::TypeBoolean) = true;

        // add sni bypass list
        item.add("sni_filter_bypass", Setting::TypeArray);
        item.add("redirect_warning_ports", Setting::TypeArray);

        item.add("failed_certcheck_replacement", Setting::TypeBoolean) = true;
        item.add("failed_certcheck_override", Setting::TypeBoolean) = true;
        item.add("failed_certcheck_override_timeout", Setting::TypeInt) = 600;
        item.add("failed_certcheck_override_timeout_type", Setting::TypeInt) = 0;
        item.add("sni_based_cert", Setting::TypeBoolean) = true;
        item.add("ip_based_cert", Setting::TypeBoolean) = true;
        item.add("only_custom_certs", Setting::TypeBoolean) = false;


        item.add("left_disable_reuse", Setting::TypeBoolean) = false;
        item.add("right_disable_reuse", Setting::TypeBoolean) = false;
        item.add("sslkeylog", Setting::TypeBoolean) = false;
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }

    return true;
}

int CfgFactory::save_tls_profiles(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("tls_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_prof_tls) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileTls>(it.second);
        if(! obj) continue;

        Setting& item = objects.add(name, Setting::TypeGroup);

        item.add("inspect", Setting::TypeBoolean) = obj->inspect;
        item.add("no_fallback_bypass", Setting::TypeBoolean) = obj->no_fallback_bypass;

        item.add("use_pfs", Setting::TypeBoolean) = obj->use_pfs;
        item.add("left_use_pfs", Setting::TypeBoolean) = obj->left_use_pfs;
        item.add("right_use_pfs", Setting::TypeBoolean) = obj->right_use_pfs;

        item.add("allow_untrusted_issuers", Setting::TypeBoolean) = obj->allow_untrusted_issuers;
        item.add("allow_invalid_certs", Setting::TypeBoolean) = obj->allow_invalid_certs;
        item.add("allow_self_signed", Setting::TypeBoolean) = obj->allow_self_signed;

        item.add("ocsp_mode", Setting::TypeInt) = obj->ocsp_mode;
        item.add("ocsp_stapling", Setting::TypeBoolean) = obj->ocsp_stapling;
        item.add("ocsp_stapling_mode", Setting::TypeInt) = obj->ocsp_stapling_mode;

        item.add("ct_enable", Setting::TypeBoolean) = obj->opt_ct_enable;

        item.add("alpn_block", Setting::TypeBoolean) = obj->opt_alpn_block;

        // add sni bypass list
        if(obj->sni_filter_bypass && ! obj->sni_filter_bypass->empty() ) {
            Setting& sni_flist = item.add("sni_filter_bypass", Setting::TypeArray);

            for( auto const& snif: *obj->sni_filter_bypass) {
                sni_flist.add(Setting::TypeString) = snif;
            }
        }

        // add redirected ports (for replacements)
        if( obj->redirect_warning_ports.ptr() && ! obj->redirect_warning_ports.ptr()->empty() ) {

            Setting& rport_list = item.add("redirect_warning_ports", Setting::TypeArray);

            for( auto rport: *obj->redirect_warning_ports.ptr()) {
                rport_list.add(Setting::TypeInt) = rport;
            }
        }
        item.add("failed_certcheck_replacement", Setting::TypeBoolean) = obj->failed_certcheck_replacement;
        item.add("failed_certcheck_override", Setting::TypeBoolean) = obj->failed_certcheck_override;
        item.add("failed_certcheck_override_timeout", Setting::TypeInt) = obj->failed_certcheck_override_timeout;
        item.add("failed_certcheck_override_timeout_type", Setting::TypeInt) = obj->failed_certcheck_override_timeout_type;
        item.add("sni_based_cert", Setting::TypeBoolean) = obj->mitm_cert_sni_search;
        item.add("ip_based_cert", Setting::TypeBoolean) = obj->mitm_cert_ip_search;
        item.add("only_custom_certs", Setting::TypeBoolean) = obj->mitm_cert_searched_only;


        item.add("left_disable_reuse", Setting::TypeBoolean) = obj->left_disable_reuse;
        item.add("right_disable_reuse", Setting::TypeBoolean) = obj->right_disable_reuse;
        item.add("sslkeylog", Setting::TypeBoolean) = obj->sslkeylog;

        n_saved++;
    }



    return n_saved;
}


bool CfgFactory::new_alg_dns_profile(Setting &ex, const std::string &name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);

        item.add("match_request_id", Setting::TypeBoolean) = false;
        item.add("randomize_id", Setting::TypeBoolean) = false;
        item.add("cached_responses", Setting::TypeBoolean) = false;
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }
    return true;
}

int CfgFactory::save_alg_dns_profiles(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("alg_dns_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_prof_alg_dns) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileAlgDns>(it.second);
        if(! obj) continue;

        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("match_request_id", Setting::TypeBoolean) = obj->match_request_id;
        item.add("randomize_id", Setting::TypeBoolean) = obj->randomize_id;
        item.add("cached_responses", Setting::TypeBoolean) = obj->cached_responses;

        n_saved++;
    }

    return n_saved;
}

bool CfgFactory::new_auth_profile (Setting &ex, const std::string &name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);

        item.add("authenticate", Setting::TypeBoolean) = false;
        item.add("resolve", Setting::TypeBoolean) = true;

        item.add("identities", Setting::TypeGroup);
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }
    return true;
}

int CfgFactory::save_auth_profiles(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("auth_profiles", Setting::TypeGroup);

    int n_saved = 0;

    for (auto const& it: CfgFactory::get()->db_prof_auth) {
        auto name = it.first;
        auto obj = std::dynamic_pointer_cast<ProfileAuth>(it.second);
        if(! obj) continue;


        Setting& item = objects.add(name, Setting::TypeGroup);
        item.add("authenticate", Setting::TypeBoolean) = obj->authenticate;
        item.add("resolve", Setting::TypeBoolean) = obj->resolve;

        if(! obj->sub_policies.empty()) {

            Setting& ident = item.add("identities", Setting::TypeGroup);

            for( auto const& identity: obj->sub_policies) {
                Setting& subid = ident.add(identity->element_name(), Setting::TypeGroup);

                if(identity->profile_detection)
                    subid.add("detection_profile", Setting::TypeString) = identity->profile_detection->element_name();

                if(identity->profile_tls)
                    subid.add("tls_profile", Setting::TypeString) = identity->profile_tls->element_name();

                if(identity->profile_content)
                    subid.add("content_profile", Setting::TypeString) = identity->profile_content->element_name();

                if(identity->profile_alg_dns)
                    subid.add("alg_dns_profile", Setting::TypeString) = identity->profile_alg_dns->element_name();

            }
        }

        n_saved++;
    }

    return n_saved;
}


bool CfgFactory::new_policy (Setting &ex, const std::string &name) const {

    try {
        auto& newpol = ex.add(Setting::TypeGroup);
        newpol.add("disabled", Setting::TypeBoolean) = true;
        newpol.add("name", Setting::TypeString);

        newpol.add("proto", Setting::TypeString) = "tcp";

        newpol.add("src", Setting::TypeArray);
        newpol.add("sport", Setting::TypeArray);
        newpol.add("dst", Setting::TypeArray);
        newpol.add("dport", Setting::TypeArray);

        newpol.add("features", Setting::TypeArray);

        newpol.add("action", Setting::TypeString) = "accept";
        newpol.add("nat", Setting::TypeString) = "auto";

        newpol.add("tls_profile", Setting::TypeString);
        newpol.add("detection_profile", Setting::TypeString);
        newpol.add("content_profile", Setting::TypeString);
        newpol.add("auth_profile", Setting::TypeString);
        newpol.add("alg_dns_profile", Setting::TypeString);
        newpol.add("routing", Setting::TypeString);
    }
    catch(libconfig::SettingNameException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }
    catch(libconfig::SettingTypeException const& e) {
        _war("cannot add new section %s: %s", name.c_str(), e.what());
        return false;
    }

    return true;
}


// libconfig API is lacking cloning facility despite it's really trivial to implement:
void CfgFactory::cfg_clone_setting(Setting& dst, Setting& orig, int index ) {


    std::string orig_name;
    if(orig.getName()) {
        orig_name = orig.getName();
    }

    //cli_print(debug_cli, "clone start: name: %s, len: %d", orig_name.c_str(), orig.getLength());

    for (unsigned int i = 0; i < (unsigned int) orig.getLength(); i++) {

        if( index >= 0 && index != (int)i) {
            continue;
        }

        Setting &cur_object = orig[(int)i];


        Setting::Type type = cur_object.getType();

        std::string name;
        if(cur_object.getName()) {
            name = cur_object.getName();
        }


        Setting& new_setting =  name.empty() ? dst.add(type) : dst.add(name.c_str(), type);

        if(cur_object.isScalar()) {
            switch(type) {
                case Setting::TypeInt:
                    new_setting = (int)cur_object;
                    break;

                case Setting::TypeInt64:
                    new_setting = (long long int)cur_object;

                    break;

                case Setting::TypeString:
                    new_setting = (const char*)cur_object;
                    break;

                case Setting::TypeFloat:
                    new_setting = (float)cur_object;
                    break;

                case Setting::TypeBoolean:
                    new_setting = (bool)cur_object;
                    break;

                default:
                    // well, that sucks. Unknown type and no way to convert or report
                    break;
            }
        }
        else {
            // index is always here -1, we don't filter sub-items
            cfg_clone_setting(new_setting, cur_object, -1 /*, debug_cli */ );
        }
    }
}

int CfgFactory::cfg_write(Config& cfg, FILE* where, unsigned long iobufsz) {

    int fds[2];
    int fret = pipe(fds);
    if(0 != fret) {
        return -1;
    }

    FILE* fw = fdopen(fds[1], "w");
    FILE* fr = fdopen(fds[0], "r");


    // set pipe buffer size to 10MB - we need to fit whole config into it.
    unsigned long nbytes = 10*1024*1024;
    if(iobufsz > 0) {
        nbytes = iobufsz;
    }

    ioctl(fds[0], FIONREAD, &nbytes);
    ioctl(fds[1], FIONREAD, &nbytes);

    cfg.write(fw);
    fclose(fw);


    int c = EOF;
    do {
        c = fgetc(fr);
        //cli_print(cli, ">>> 0x%x", c);

        switch(c) {
            case EOF:
                break;

            case '\n':
                fputc('\r', where);
                // omit break - so we write also '\n'

                [[fallthrough]];

            default:
                fputc(c, where);
        }

    } while(c != EOF);


    fclose(fr);

    return 0;
}

size_t CfgFactory::section_list_size(std::string const& section) const {
    if(section == "policy") {
        return db_policy_list.size();
    }
    return 0;
}

bool CfgFactory::_apply_new_entry(std::string const& section, std::string const& entry_name) {

    bool added = false;

    Setting &s = cfg_root().lookup(section.c_str());
    if(section == "proto_objects") {
        if (CfgFactory::get()->new_proto_object(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_proto();
        }
    }
    else if(section == "port_objects") {
        if (CfgFactory::get()->new_port_object(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_port();
        }
    }
    else if(section == "address_objects") {
        if (CfgFactory::get()->new_address_object(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_address();
        }
    }
    else if(section == "detection_profiles") {
        if (CfgFactory::get()->new_detection_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_detection();
        }
    }
    else if(section == "content_profiles") {
        if (CfgFactory::get()->new_content_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_content();
        }
    }
    else if(section == "tls_ca") {
        if (CfgFactory::get()->new_tls_ca(s, entry_name)) {
            added = true;
            // missing load_db_tls_ca
        }
    }
    else if(section == "tls_profiles") {
        if (CfgFactory::get()->new_tls_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_tls();
        }
    }
    else if(section == "alg_dns_profiles") {
        if (CfgFactory::get()->new_alg_dns_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_alg_dns();
        }
    }
    else if(section == "auth_profiles") {
        if (CfgFactory::get()->new_auth_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_auth();
        }
    }
    else if(section == "policy") {
        // policy is unnamed list, ignore argument and add index
        if (CfgFactory::get()->new_policy(s, string_format("[%d]", CfgFactory::get()->db_policy_list.size()))) {
            added = true;

            // policy is a list - it must be cleared before loaded again
            CfgFactory::get()->cleanup_db_policy();
            CfgFactory::get()->load_db_policy();
        }
    }
    else if(section == "routing") {
        if (CfgFactory::get()->new_routing(s, entry_name)) {
            added = true;
            // policy is a list - it must be cleared before loaded again
            CfgFactory::get()->load_db_routing();
        }
    }

    return added;
}

std::pair<bool, std::string> CfgFactory::cfg_add_prepare_params(std::string const& section, std::vector<std::string>& args) {

    bool section_is_list = CfgFactory::section_lists.find(section) != CfgFactory::section_lists.end();

    std::for_each(args.begin(), args.end(), [](auto& e) {
        // allow only ascii characters
        e = escape(e, true, true);
    });

    if (not args.empty()) {
        if(args[0] == "?") {
            return { false, "Note: add <object_name> (name must not start with reserved __)" };
        }
        else if(args[0].find("__") == 0) {
            return { false, "Error: name must not start with reserved \'__\'" };
        }
        else if(section_is_list) {

            args.clear();
            args.push_back(string_format("[%d]", CfgFactory::get()->section_list_size(section)));

            return { true, "Note: suggested name is ignored in unnamed lists" };
        }
    }
    else {
        // allow empty args for policy
        if (section_is_list) {
            args.clear();
            args.push_back(string_format("[%d]", CfgFactory::get()->section_list_size(section)));
        }
        else {
            return { false, "Error: new entry in this section must have an unique name." };
        }
    }

    return { true, "" };
};

std::pair<bool, std::string> CfgFactory::cfg_add_entry(std::string const& section_name, std::string const& entry_name) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if (CfgFactory::cfg_root().exists(section_name.c_str())) {

        if (CfgFactory::_apply_new_entry(section_name, entry_name)) {

            return { true, string_format("Note: %s.%s has been created.", section_name.c_str(), entry_name.c_str()) };
        }
        else {
            return { false, "Error: entry not created" };
        }
    }
    else {
        return { false, "Error: section does not exist" };
    }
}

std::optional<int> make_int(std::string const& v)  {
    if(v.empty())
        return 0;

    return std::stoi(v);
}

std::optional<long long int> make_lli(std::string const& v) {

    if(v.empty())
        return 0L;

    return std::stoll(v);
}


std::optional<bool> make_bool(std::string const& v) {

    if(v.empty())
        return true;

    auto uv = string_tolower(v);
    if (uv == "true" or uv == "1" or uv == "yes" or uv == "y" or uv == "t") {
        return true;
    } else if (uv == "false" or uv == "0" or uv == "no" or uv == "n" or uv == "f") {
        return false;
    } else {
        return std::nullopt;
    }
}

std::optional<float> make_float(std::string const& v) {

    if(v.empty())
        return 0.0f;

    return std::stof(v);
}

bool CfgFactory::write_value(Setting& setting, std::optional<std::string> string_value, Setting::Type add_as_type) {

    bool ret_verdict = false;
    std::string original_value;

    if(string_value.has_value()) {
        original_value = string_value.value();
    }

    auto [ verdict, msg ] = CfgValueHelp::get().value_check(setting.getPath(), original_value);
    if(verdict.has_value()) {
        original_value = verdict.value();
    } else {
        return false;
    }


    auto setting_type = setting.getType();
    if(add_as_type != Setting::TypeNone)
        setting_type = add_as_type;

    std::any converted_value;
    switch(setting_type) {
        case Setting::TypeInt: {
            auto a = make_int(original_value);
            if (a.has_value()) converted_value = a.value();
        }
            break;

        case Setting::TypeInt64: {
            auto a = make_lli(original_value);
            if(a.has_value()) converted_value = a.value();
        }
            break;

        case Setting::TypeBoolean: {
            auto a = make_bool(original_value);
            if (a.has_value()) converted_value = a.value();
        }
            break;

        case Setting::TypeFloat: {
            auto a = make_float(original_value);
            if(a.has_value()) converted_value = a.value();
        }
            break;
        case Setting::TypeString:
            converted_value = original_value;
            break;

        case Setting::TypeNone:
            throw std::logic_error("write value cannot be used for TypeNone");
            break;
        case Setting::TypeGroup:
            throw std::logic_error("write value cannot be used for TypeGroup");
            break;
        case Setting::TypeArray:
            throw std::logic_error("write value cannot be used for TypeArray");
            break;
        case Setting::TypeList:
            throw std::logic_error("write value cannot be used for TypeList");
            break;
    }

    if (converted_value.has_value()) {

        switch(setting_type) {
            case Setting::TypeInt: {
                auto value = std::any_cast<int>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeInt) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
                break;

            case Setting::TypeInt64: {
                auto value = std::any_cast<long long int>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeInt64) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
                break;

            case Setting::TypeBoolean: {
                auto value = std::any_cast<bool>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeBoolean) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
                break;

            case Setting::TypeFloat: {
                auto value = std::any_cast<float>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeFloat) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
                break;

            case Setting::TypeString: {
                auto value = std::any_cast<std::string>(converted_value);
                if(add_as_type != Setting::TypeNone) {
                    setting.add(Setting::TypeString) = value;
                } else {
                    setting = value;
                }

                ret_verdict = true;
            }
                break;

            case Setting::TypeNone:
                throw std::logic_error("write value cannot be used for TypeNone");
                break;
            case Setting::TypeGroup:
                throw std::logic_error("write value cannot be used for TypeGroup");
                break;
            case Setting::TypeArray:
                throw std::logic_error("write value cannot be used for TypeArray");
                break;
            case Setting::TypeList:
                throw std::logic_error("write value cannot be used for TypeList");
                break;
        }

    }

    return ret_verdict;
}


std::pair<bool, std::string> CfgFactory::cfg_write_value(Setting& parent, bool create, std::string& varname, const std::vector<std::string> &values) {

    bool ret_verdict = true;
    std::string ret_msg;

    bool no_args_erases_array = true;


    if( parent.exists(varname.c_str()) ) {

        _not("config item exists %s", varname.c_str());

        Setting& setting = parent[varname.c_str()];
        auto setting_type = setting.getType();

        std::string lvalue;

        try {
            switch (setting_type) {
                case Setting::TypeInt:
                case Setting::TypeInt64:
                case Setting::TypeBoolean:
                case Setting::TypeFloat:
                case Setting::TypeString:

                    if(not values.empty()) {

                        // write only first value into scalar
                        ret_verdict = write_value(setting, values[0]);
                    }
                    else {
                        ret_verdict = write_value(setting, std::nullopt);
                    }
                    break;


                case Setting::TypeArray:
                {
                    auto first_elem_type = Setting::TypeString;
                    if ( setting.getLength() > 0 ) {
                        first_elem_type = setting[0].getType();
                    }

                    std::vector<std::string> consolidated_values;
                    for(auto const &v: values) {
                        auto arg_values = string_split(v, ',');

                        for (auto const &av: arg_values)
                            consolidated_values.push_back(av);
                    }

                    // check values
                    for(auto const& i: consolidated_values) {

                        auto [ verdict, msg ]  = CfgValueHelp::get().value_check(setting.getPath(), i);

                        if(not verdict) {
                            ret_verdict = false;
                            ret_msg = msg;
                            break;
                        }
                    }

                    if(ret_verdict) {
                        if (not consolidated_values.empty() or no_args_erases_array) {

                            // ugly (but only) way to remove
                            for (int x = setting.getLength() - 1; x >= 0; x--) {
                                setting.remove(x);
                            }

                            for(auto const& cons_val: consolidated_values) {
                                ret_verdict = write_value(setting, cons_val, first_elem_type);
                            }

                        } else {
                            throw (std::invalid_argument("no valid arguments"));
                        }
                    }
                }

                    break;

                default:
                    ;
            }
        }
        catch(std::bad_any_cast const& e) {
            ret_msg = "invalid value conversion";
            ret_verdict = false;
        }
        catch(std::invalid_argument const& e) {
            ret_msg ="invalid argument!";
            ret_verdict = false;
        }
        catch(std::exception const& e) {
            ret_msg = string_format( "error writing config variable: %s", e.what());
            ret_verdict = false;
        }
    }
    else if(create) {
        _err("nyi: error writing creating a new config variable: %s", varname.c_str());
        ret_verdict = false;
    } else {
        _err("cli error: no such attribute name: %s", varname.c_str());
        ret_verdict = false;
    }

    return { ret_verdict, ret_msg };
}


bool CfgFactory::move_policy (int what, int where, op_move op) {

    bool ret = false;

    auto cfg_remove_all = [](Setting& objects) {
        for(int i = objects.getLength() - 1; i >= 0; i--) {
            objects.remove(i);
        }
    };

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Config backup;

#if ( LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7 )
    backup.setOptions(Setting::OptionOpenBraceOnSeparateLine);
#else
    backup.setOptions(Config::OptionOpenBraceOnSeparateLine);
#endif
    backup.setTabWidth(4);

    try {
        auto &policy_list = backup.getRoot().add("policy", Setting::TypeList);

        if(cfg_root().exists("policy")) {
            Setting &orig_policy_list = cfg_root()["policy"];

            cfg_clone_setting(policy_list, orig_policy_list, -1);
            cfg_remove_all(orig_policy_list);

            for(int i = 0; i < policy_list.getLength(); i++) {
                if(i == what) {
                    continue;
                }
                else {
                    if (op == op_move::OP_MOVE_BEFORE and i == where) {
                        auto &cur2 = orig_policy_list.add(Setting::TypeGroup);
                        cfg_clone_setting(cur2, policy_list[what], -1);
                    }

                    auto &cur = orig_policy_list.add(Setting::TypeGroup);
                    cfg_clone_setting(cur, policy_list[i], -1);

                    if (op == op_move::OP_MOVE_AFTER and i == where) {
                        auto &cur2 = orig_policy_list.add(Setting::TypeGroup);
                        cfg_clone_setting(cur2, policy_list[what], -1);
                    }
                }
            }

            ret = true;
        }
    }
    catch(std::exception const& e) {
        _err("move_policy: error - %s", e.what());
    }

    return ret;
}


int CfgFactory::save_policy(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Setting& objects = ex.getRoot().add("policy", Setting::TypeList);

    int n_saved = 0;

    for (auto const& pol: CfgFactory::get()->db_policy_list) {

        if(! pol)
            continue;

        Setting& item = objects.add(Setting::TypeGroup);

        item.add("disabled", Setting::TypeBoolean) = pol->is_disabled;
        item.add("name", Setting::TypeString) = pol->policy_name;

        item.add("proto", Setting::TypeString) = pol->proto->element_name();

        // SRC
        Setting& src_list = item.add("src", Setting::TypeArray);
        for(auto const& s: pol->src) {
            src_list.add(Setting::TypeString) = s->element_name();
        }
        Setting& srcport_list = item.add("sport", Setting::TypeArray);
        for(auto const& sp: pol->src_ports) {
            srcport_list.add(Setting::TypeString) = sp->element_name();
        }


        // DST
        Setting& dst_list = item.add("dst", Setting::TypeArray);
        for(auto const& d: pol->dst) {
            dst_list.add(Setting::TypeString) = d->element_name();
        }
        Setting& dstport_list = item.add("dport", Setting::TypeArray);
        for(auto const& sp: pol->dst_ports) {
            dstport_list.add(Setting::TypeString) = sp->element_name();
        }

        Setting& features_list = item.add("features", Setting::TypeArray);
        for(auto const& f: pol->features) {
            features_list.add(Setting::TypeString) = f->element_name();
        }

        item.add("action", Setting::TypeString) = pol->action_name;
        item.add("nat", Setting::TypeString) = pol->nat_name;

        if(pol->profile_routing)
            item.add("routing", Setting::TypeString) = pol->profile_routing->element_name();
        else
            item.add("routing", Setting::TypeString) = "none";

        if(pol->profile_tls)
            item.add("tls_profile", Setting::TypeString) = pol->profile_tls->element_name();
        if(pol->profile_detection)
            item.add("detection_profile", Setting::TypeString) = pol->profile_detection->element_name();
        if(pol->profile_content)
            item.add("content_profile", Setting::TypeString) = pol->profile_content->element_name();
        if(pol->profile_auth)
            item.add("auth_profile", Setting::TypeString) = pol->profile_auth->element_name();
        if(pol->profile_alg_dns)
            item.add("alg_dns_profile", Setting::TypeString) = pol->profile_alg_dns->element_name();

        n_saved++;
    }

    return n_saved;
}

int save_signatures(Config& ex, const std::string& sigset) {

    auto save_target = [](Config& ex, auto& target, std::string const& sigset_name) -> int {
        std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

        Setting& objects = ex.getRoot().exists(sigset_name) ? ex.getRoot()[sigset_name.c_str()] : ex.getRoot().add(sigset_name, Setting::TypeList);

        int n_saved = 0;

        auto& target_ref = *target;
        for (auto const&[_, sig]: target_ref) {

            Setting &item = objects.add(Setting::TypeGroup);

            item.add("name", Setting::TypeString) = sig->name();


            auto my_sig = dynamic_cast<MyDuplexFlowMatch *>(sig.get());

            if (my_sig) {
                item.add("cat", Setting::TypeString) = my_sig->sig_category;
                item.add("side", Setting::TypeString) = my_sig->sig_side;
                item.add("severity", Setting::TypeInt) = my_sig->sig_severity;
                item.add("group", Setting::TypeString) = my_sig->sig_group;
                item.add("enables", Setting::TypeString) = my_sig->sig_enables;
                item.add("engine", Setting::TypeString) = my_sig->sig_engine;
            }

            if (!sig->sig_chain().empty()) {

                Setting &flow = item.add("flow", Setting::TypeList);

                for (auto& [ sig_side, bm ]: sig->sig_chain()) {

                    bool sig_correct = false;

                    unsigned int sig_bytes_start = bm->match_limits_offset;
                    unsigned int sig_bytes_max = bm->match_limits_bytes;
                    std::string sig_type;
                    std::string sig_expr;


                    // follow the inheritance (regex can also be cast to simple)
                    auto rm = dynamic_cast<regexMatch *>(bm.get());
                    if (rm) {
                        sig_type = "regex";
                        sig_expr = rm->expr();
                        sig_correct = true;
                    } else {
                        auto sm = dynamic_cast<simpleMatch *>(bm.get());
                        if (sm) {
                            sig_type = "simple";
                            sig_expr = sm->expr();
                            sig_correct = true;
                        }
                    }


                    if (sig_correct) {
                        Setting &flow_match = flow.add(Setting::TypeGroup);
                        flow_match.add("side", Setting::TypeString) = string_format("%c", sig_side);
                        flow_match.add("type", Setting::TypeString) = sig_type;
                        flow_match.add("bytes_start", Setting::TypeInt) = (int) sig_bytes_start;
                        flow_match.add("bytes_max", Setting::TypeInt) = (int) sig_bytes_max;
                        flow_match.add("signature", Setting::TypeString) = sig_expr;
                    } else {
                        Setting &flow_match = flow.add(Setting::TypeGroup);
                        flow_match.add("comment", Setting::TypeString) = "???";
                    }
                }
            }


            n_saved++;
        }

        return n_saved;
    };


    int total = 0;

    if(sigset == "starttls_signatures") {
        auto target = SigFactory::get().tls();
        if(target)
            total += save_target(ex, target, sigset);
    }
    else if(sigset == "detection_signatures") {
        auto target = SigFactory::get().base();
        if(target)
            total += save_target(ex, target, sigset);
    }
    else {
        auto target = SigFactory::get().signature_tree().group(sigset.c_str(), false);
        total += save_target(ex, target, "detection_signatures");
    }

    return total;

}

int save_internal(Config& ex) {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(!ex.exists("*_internal_*"))
        ex.getRoot().add("*_internal_*", Setting::TypeGroup);

    Setting& objects = ex.getRoot()["*_internal_*"];
    objects.add("version", Setting::TypeString) = SMITH_VERSION;
    objects.add("schema", Setting::TypeInt) = CfgFactory::get()->schema_version;

    return 1;
}

int save_settings(Config& ex) {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(!ex.exists("settings"))
        ex.getRoot().add("settings", Setting::TypeGroup);

    Setting& objects = ex.getRoot()["settings"];


    objects.add("accept_tproxy", Setting::TypeBoolean) = CfgFactory::get()->accept_tproxy;
    objects.add("accept_redirect", Setting::TypeBoolean) = CfgFactory::get()->accept_redirect;
    objects.add("accept_socks", Setting::TypeBoolean) = CfgFactory::get()->accept_socks;

    // nameservers
    Setting& it_ns  = objects.add("nameservers", Setting::TypeArray);
    for(auto const& ns: CfgFactory::get()->db_nameservers) {
        it_ns.add(Setting::TypeString) = ns.str_host;
    }

    objects.add("certs_path", Setting::TypeString) = SSLFactory::factory().certs_path();
    objects.add("certs_ca_key_password", Setting::TypeString) = SSLFactory::factory().certs_password();
    objects.add("certs_ctlog", Setting::TypeString) = SSLFactory::factory().ctlogfile();
    objects.add("ca_bundle_path", Setting::TypeString) = SSLFactory::factory().ca_path();
    objects.add("ca_bundle_file", Setting::TypeString) = SSLFactory::factory().ca_file();

    objects.add("plaintext_port", Setting::TypeString) = CfgFactory::get()->listen_tcp_port_base;
    objects.add("plaintext_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_tcp;

    objects.add("ssl_port", Setting::TypeString) = CfgFactory::get()->listen_tls_port_base;
    objects.add("ssl_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_tls;
    objects.add("ssl_autodetect", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect;
    objects.add("ssl_autodetect_harder", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect_harder;
    objects.add("ssl_ocsp_status_ttl", Setting::TypeInt) = SSLFactory::options::ocsp_status_ttl;
    objects.add("ssl_crl_status_ttl", Setting::TypeInt) = SSLFactory::options::crl_status_ttl;
    objects.add("ssl_use_ktls", Setting::TypeBoolean) = SSLFactory::options::ktls;

    objects.add("udp_port", Setting::TypeString) = CfgFactory::get()->listen_udp_port_base;
    objects.add("udp_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_udp;

    objects.add("dtls_port", Setting::TypeString) = CfgFactory::get()->listen_dtls_port_base;
    objects.add("dtls_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_dtls;

    //udp quick ports
    Setting& it_quick  = objects.add("udp_quick_ports", Setting::TypeArray);
    if(CfgFactory::get()->db_udp_quick_ports.empty()) {
        it_quick.add(Setting::TypeInt) = 0;
    }
    else {
        for (auto p: CfgFactory::get()->db_udp_quick_ports) {
            it_quick.add(Setting::TypeInt) = p;
        }
    }

    objects.add("socks_port", Setting::TypeString) = CfgFactory::get()->listen_socks_port_base;
    objects.add("socks_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_socks;

    Setting& socks_objects = objects.add("socks", Setting::TypeGroup);
    socks_objects.add("async_dns", Setting::TypeBoolean) = socksServerCX::global_async_dns;
    socks_objects.add("ipver_mixing", Setting::TypeBoolean) =  socksServerCX::mixed_ip_versions;
    socks_objects.add("prefer_ipv6", Setting::TypeBoolean) = socksServerCX::prefer_ipv6;


    objects.add("log_level", Setting::TypeInt) = static_cast<int>(CfgFactory::get()->internal_init_level.level_ref());
    objects.add("log_file", Setting::TypeString) = CfgFactory::get()->log_file_base;
    objects.add("log_console", Setting::TypeBoolean)  = CfgFactory::get()->log_console;

    objects.add("syslog_server", Setting::TypeString) = CfgFactory::get()->syslog_server;
    objects.add("syslog_port", Setting::TypeInt) = CfgFactory::get()->syslog_port;
    objects.add("syslog_facility", Setting::TypeInt) = CfgFactory::get()->syslog_facility;
    objects.add("syslog_level", Setting::TypeInt) = (int)CfgFactory::get()->syslog_level.level_ref();
    objects.add("syslog_family", Setting::TypeInt) = CfgFactory::get()->syslog_family;

    objects.add("sslkeylog_file", Setting::TypeString) = CfgFactory::get()->sslkeylog_file_base;
    objects.add("messages_dir", Setting::TypeString) = CfgFactory::get()->dir_msg_templates;

    Setting& admin_objects = objects.add("admin", Setting::TypeGroup);
    admin_objects.add("group", Setting::TypeString) = CfgFactory::get()->admin_group;

    Setting& cli_objects = objects.add("cli", Setting::TypeGroup);
    cli_objects.add("port", Setting::TypeInt) = CfgFactory::get()->cli_port_base;
    cli_objects.add("enable_password", Setting::TypeString) = CfgFactory::get()->cli_enable_password;

    Setting& auth_objects = objects.add("auth_portal", Setting::TypeGroup);
    auth_objects.add("address", Setting::TypeString) = CfgFactory::get()->auth_address;
    auth_objects.add("http_port", Setting::TypeString) = CfgFactory::get()->auth_http;
    auth_objects.add("https_port", Setting::TypeString) = CfgFactory::get()->auth_https;
    auth_objects.add("ssl_key", Setting::TypeString) = CfgFactory::get()->auth_sslkey;
    auth_objects.add("ssl_cert", Setting::TypeString) = CfgFactory::get()->auth_sslcert;


    Setting& tuning_objects = objects.add("tuning", Setting::TypeGroup);
    tuning_objects.add("proxy_thread_spray_min", Setting::TypeInt) = (int)MasterProxy::subproxy_thread_spray_min;
    tuning_objects.add("subproxy_thread_spray_bytes_min", Setting::TypeInt) = (int)MasterProxy::subproxy_thread_spray_bytes_min;
    tuning_objects.add("host_bufsz_min", Setting::TypeInt) = (int) baseHostCX::params.buffsize;
    tuning_objects.add("host_bufsz_max_multiplier", Setting::TypeInt) = (int) baseHostCX::params.buffsize_maxmul;
    tuning_objects.add("host_write_full", Setting::TypeInt) = (int) baseHostCX::params.write_full;


    objects.add("accept_api", Setting::TypeBoolean) = CfgFactory::get()->accept_api;
    Setting& http_api_objects = objects.add("http_api", Setting::TypeGroup);

    Setting& keys = http_api_objects.add("keys", Setting::TypeArray);
    for(auto const& k: sx::webserver::HttpSessions::api_keys) {
        keys.add(Setting::TypeString) = k;
    }
    http_api_objects.add("key_timeout", Setting::TypeInt) = (int)sx::webserver::HttpSessions::session_ttl;
    http_api_objects.add("key_extend_on_access", Setting::TypeBoolean) = (bool)sx::webserver::HttpSessions::extend_on_access;
    http_api_objects.add("loopback_only", Setting::TypeBoolean) = (bool)sx::webserver::HttpSessions::loopback_only;
    http_api_objects.add("bind_address", Setting::TypeString) = sx::webserver::HttpSessions::bind_address;
    http_api_objects.add("bind_interface", Setting::TypeString) = sx::webserver::HttpSessions::bind_interface;

    Setting& allowed_ips = http_api_objects.add("allowed_ips", Setting::TypeArray);
    for (auto const& ip: sx::webserver::HttpSessions::allowed_ips) {
        allowed_ips.add(Setting::TypeString) = ip;
    }

    http_api_objects.add("port", Setting::TypeInt) = sx::webserver::HttpSessions::api_port;
    http_api_objects.add("pam_login", Setting::TypeBoolean) = (bool)sx::webserver::HttpSessions::pam_login;


    Setting& webhook_objects = objects.add("webhook", Setting::TypeGroup);
    webhook_objects.add("enabled", Setting::TypeBoolean) = CfgFactory::get()->settings_webhook.enabled;
    webhook_objects.add("url", Setting::TypeString) = CfgFactory::get()->settings_webhook.cfg_url;
    webhook_objects.add("tls_verify", Setting::TypeBoolean) = CfgFactory::get()->settings_webhook.cfg_tls_verify;
    webhook_objects.add("hostid", Setting::TypeString) = CfgFactory::get()->settings_webhook.hostid;
    webhook_objects.add("bind_interface", Setting::TypeString) = CfgFactory::get()->settings_webhook.bind_interface;
    webhook_objects.add("api_override", Setting::TypeBoolean) = CfgFactory::get()->settings_webhook.allow_api_override;

    return 0;
}

#ifdef USE_EXPERIMENT
int CfgFactory::save_experiment(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(not ex.exists("experiment"))
        ex.getRoot().add("experiment", Setting::TypeGroup);

    Setting& exper = ex.getRoot()["experiment"];

    exper.add("enabled_1", Setting::TypeBoolean) = CfgFactory::get()->experiment_1.enabled;
    exper.add("param_1", Setting::TypeString) = CfgFactory::get()->experiment_1.param;

    return 1;
}
#endif


int CfgFactory::save_captures(Config& ex) const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    if(not ex.exists("captures"))
        ex.getRoot().add("captures", Setting::TypeGroup);

    Setting& objects = ex.getRoot()["captures"];

    if(not objects.exists("local"))
        objects.add("local", Setting::TypeGroup);


    auto& local = ex.getRoot()["captures"]["local"];
    local.add("enabled", Setting::TypeBoolean) = CfgFactory::get()->capture_local.enabled;
    local.add("dir", Setting::TypeString) = CfgFactory::get()->capture_local.dir;
    local.add("file_prefix", Setting::TypeString) = CfgFactory::get()->capture_local.file_prefix;
    local.add("file_suffix", Setting::TypeString) = CfgFactory::get()->capture_local.file_suffix;
    local.add("pcap_quota", Setting::TypeInt) = static_cast<int>(traflog::PcapLog::single_instance().stat_bytes_quota/(1024*1024));
    local.add("format", Setting::TypeString) = CfgFactory::get()->capture_local.format.to_str();


    if(not objects.exists("remote"))
        objects.add("remote", Setting::TypeGroup);


    auto& remote = ex.getRoot()["captures"]["remote"];
    remote.add("enabled", Setting::TypeBoolean) = CfgFactory::get()->capture_remote.enabled;
    remote.add("tun_type", Setting::TypeString) = CfgFactory::get()->capture_remote.tun_type;
    remote.add("tun_dst", Setting::TypeString) = CfgFactory::get()->capture_remote.tun_dst;
    remote.add("tun_ttl", Setting::TypeInt) = CfgFactory::get()->capture_remote.tun_ttl;


    if(not objects.exists("options"))
        objects.add("options", Setting::TypeGroup);

    auto& options = ex.getRoot()["captures"]["options"];
    options.add("calculate_checksums", Setting::TypeBoolean) = socle::pcap::CONFIG::CALCULATE_CHECKSUMS;


    return 1;
}

bool CfgFactory::save_config() const {

    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    Config ex;


    #if ( LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7 )

    ex.setOptions(Setting::OptionOpenBraceOnSeparateLine);

    #else

    ex.setOptions(Config::OptionOpenBraceOnSeparateLine);

    #endif

    ex.setTabWidth(4);

    save_internal(ex);

    int n = 0;

    n = save_settings(ex);
    _inf("... common settings");

    n = save_captures(ex);

#ifdef USE_EXPERIMENT
    n = save_experiment(ex);
    _inf("... experiments (will be removed by no-experimental version)");
#endif //USE_EXPERIMENT

    _inf("... capture settings");

    n = save_debug(ex);
    _inf("... debug settings");

    n = save_address_objects(ex);
    _inf("%d address_objects", n);

    n = save_port_objects(ex);
    _inf("%d port_objects", n);

    n = save_proto_objects(ex);
    _inf("%d proto_objects", n);

    n = save_detection_profiles(ex);
    _inf("%d detection_profiles", n);

    n = save_content_profiles(ex);
    _inf("%d content_profiles", n);

    n = save_tls_ca(ex);
    _inf("%d tls_ca", n);

    n = save_tls_profiles(ex);
    _inf("%d tls_profiles", n);

    n = save_alg_dns_profiles(ex);
    _inf("%d alg_dns_profiles", n);

    n = save_auth_profiles(ex);
    _inf("%d auth_profiles", n);

    n = save_routing(ex);
    _inf("%d routing", n);

    n = save_policy(ex);
    _inf("%d policy", n);

    n = save_signatures(ex, "starttls_signatures");
    _inf("%d %s signatures", n, "starttls");

    n = save_signatures(ex, "detection_signatures");
    _inf("%d %s signatures", n, "detection/base");

    for(auto const& ni: SigFactory::get().signature_tree().name_index) {
        // avoid to copy again starttls and base
        if(ni.second < 2) continue;

        n = save_signatures(ex, ni.first);
        _inf("%d %s signatures", n, string_format("detection/%s[%d]", ni.first.c_str(), ni.second).c_str());
    }

    try {
        ex.writeFile(CfgFactory::get()->config_file.c_str());
        log.event(NOT, "Configuration saved");

        return true;
    }
    catch(ConfigException const& e) {
        _err("error writing config file %s", e.what());
        log.event(ERR, "Configuration NOT saved: %s", e.what());

        return false;
    }
}


AddressInfo const& DNS_Setup::default_ns() {
    static const auto ai = create_default_ns(AF_INET, "1.1.1.1", 53);
    return ai;
};

AddressInfo const& DNS_Setup::choose_dns_server(int pref_family) {

    auto const& db = CfgFactory::get()->db_nameservers;
    if (not db.empty()) {

        if(pref_family != 0) for(auto const& can: db) {
                if(can.family == pref_family)
                    return can;
            }
        return db.at(0);
    }
    return default_ns();
}


AddressInfo DNS_Setup::create_default_ns(int fam, const char* ip, unsigned short port) {
    AddressInfo ai;
    ai.str_host = ip;
    ai.port = port;
    ai.family = fam;
    ai.pack();

    return ai;
}