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

#include <cstdio>
#include <cstdlib>
#include <vector>

#include <socle.hpp>
#include <main.hpp>


#include <service/cfgapi/cfgapi.hpp>
#include <service/cfgapi/cfg_numeric.hpp>
#include <service/cfgapi/cfg_serialization.hpp>
#include <service/cfgapi/cfgvalue.hpp>
#include <service/privileged_file.hpp>
#include <service/cfgapi/profile_runtime_options.hpp>
#include <log/logger.hpp>

#include <policy/policy.hpp>
#include <inspect/sigfactory.hpp>
#include <inspect/sxsignature.hpp>

#include <proxy/mitmproxy.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/nbrhood.hpp>

#include <proxy/filters/sinkhole.hpp>
#include <proxy/filters/statsfilter.hpp>
#include <proxy/filters/access_filter.hpp>
#ifdef USE_LIBSSH
#include <proxy/ssh/sshstream.hpp>
#endif

#include <inspect/dnsinspector.hpp>
#include <inspect/pyinspector.hpp>

#include <service/httpd/httpd.hpp>
#include <service/http/webhooks.hpp>

using namespace libconfig;

bool CfgFactory::ct_requested() const {
    return std::any_of(db_prof_tls.begin(), db_prof_tls.end(),
        [](const auto& entry) {
            const auto profile =
                std::dynamic_pointer_cast<ProfileTls>(entry.second);
            return profile && profile->opt_ct_enable;
        });
}

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
    else if(section == "ssh_profiles" or section == "ssh_profiles.[x]") {
        return db_prof_ssh;
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
        std::string content;
        if(sx::privsep::files::config_read(fnm, content) != 0) throw FileIOException();
        cfgapi.readString(content);
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
    
    return nullptr;
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
    
    return nullptr;
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

std::shared_ptr<ProfileSsh> CfgFactory::lookup_prof_ssh (const char *name) {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    if(db_prof_ssh.find(name) != db_prof_ssh.end()) {
        return std::dynamic_pointer_cast<ProfileSsh>(db_prof_ssh[name]);
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

        if(not sx::webserver::HttpSessions::has_api_keys()) {
            sx::webserver::HttpSessions::replace_api_keys(
                    {hex_print(rand_pool, 16)});
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
    else if(upgrade_to_num == 1028) {
        log.event(INF, "added captures.remote.bind_interface");
        return true;
    }
    else if(upgrade_to_num == 1029) {
        log.event(INF, "added settings.webhook.ping_interval");
        log.event(INF, "added settings.webhook.nbr_update_interval");
        log.event(INF, "added settings.webhook.nbr_refresh_age");
        return true;
    }
    else if(upgrade_to_num == 1030) {
        log.event(INF, "added settings.tuning.open_timeout");
        log.event(INF, "added settings.tuning.idle_timeout");
        return true;
    }
    else if(upgrade_to_num == 1031) {
        log.event(INF, "added tls_profile.[x].alerts");
        return true;
    }
    else if(upgrade_to_num == 1032) {
        log.event(INF, "added settings.tpool_log");
        log.event(INF, "added settings.webhook.task_debug");
        log.event(INF, "added settings.webhook.task_debug_dump");
        return true;
    }
    else if(upgrade_to_num == 1033) {
        log.event(INF, "added settings.tuning.nbr_cache_size");
        return true;
    }
    else if(upgrade_to_num == 1034) {
        log.event(INF, "added content_profile.[x].rules_session_filter");
        return true;
    }
    else if(upgrade_to_num == 1035) {
        log.event(INF, "added content_profile.[x].ja4_tls_ch");
        return true;
    }
    else if(upgrade_to_num == 1036) {
        log.event(INF, "added content_profile.[x].ja4_tls_sh");
        return true;
    }
    else if(upgrade_to_num == 1037) {
        log.event(INF, "added content_profile.[x].ja4_http");
        return true;
    }
    else if(upgrade_to_num == 1038) {
        log.event(INF, "added content_profile.[x].ja4_tls_ch_ignore_sni");
        return true;
    }
    else if(upgrade_to_num == 1039) {
        log.event(INF, "added settings.http_api.allow_api_header (for GET)");
        return true;
    }
    else if(upgrade_to_num == 1040) {
        log.event(INF, "added settings.policy_fail_open (default false)");
        log.event(INF, "added settings.policy_access_request_fail_open (default false)");
        log.event(NOT, "policy and access-request failures now default to fail-closed");
        return true;
    }
    else if(upgrade_to_num == 1041) {
        log.event(INF, "tls_profile.[x].client_cert_action now uses named values");
        log.event(INF, "numeric client certificate actions will be saved as strings");
        return true;
    }
    else if(upgrade_to_num == 1042) {
        log.event(INF, "added tls_profiles.[x].client_hello_timeout (milliseconds)");
        log.event(INF, "added tls_profiles.[x].handshake_timeout (milliseconds)");
        return true;
    }
    else if(upgrade_to_num == 1043) {
        if(not cfgapi.getRoot().exists("ssh_profiles")) {
            cfgapi.getRoot().add("ssh_profiles", Setting::TypeGroup);
        }
        log.event(INF, "added ssh_profiles section");
        log.event(INF, "added policy.[x].ssh_profile");
        return true;
    }
    else if(upgrade_to_num == 1044) {
        if(cfgapi.getRoot().exists("policy")) {
            Setting& policies = cfgapi.getRoot()["policy"];
            for(int i = 0; i < policies.getLength(); ++i) {
                if(!policies[i].exists("ssh_profile")) {
                    policies[i].add("ssh_profile", Setting::TypeString) = "";
                }
            }
        }
        log.event(INF, "materialized policy.[x].ssh_profile");
        return true;
    }
    else if(upgrade_to_num == 1045) {
        if(cfgapi.getRoot().exists("captures") &&
           cfgapi.getRoot()["captures"].exists("remote")) {
            Setting& remote = cfgapi.getRoot()["captures"]["remote"];
            if(remote.exists("gre_format") &&
               std::string(static_cast<char const*>(remote["gre_format"])) == "spq1") {
                remote["gre_format"] = "traffic";
            }
        }
        log.event(INF, "renamed captures.remote.gre_format 'spq1' to 'traffic'");
        return true;
    }
    else if(upgrade_to_num == 1046) {
        if(cfgapi.getRoot().exists("ssh_profiles")) {
            Setting& profiles = cfgapi.getRoot()["ssh_profiles"];
            for(int i = 0; i < profiles.getLength(); ++i) {
                for(auto const* feature : {"shell", "exec", "subsystem", "pty",
                                           "environment", "local_forward",
                                           "remote_forward", "x11", "agent"}) {
                    if(!profiles[i].exists(feature)) {
                        profiles[i].add(feature, Setting::TypeString) = "pass";
                    }
                }
            }
        }
        log.event(INF, "added per-feature SSH profile actions");
        return true;
    }
    else if(upgrade_to_num == 1047) {
        if(cfgapi.getRoot().exists("ssh_profiles")) {
            Setting& profiles = cfgapi.getRoot()["ssh_profiles"];
            for(int i = 0; i < profiles.getLength(); ++i) {
                if(!profiles[i].exists("hostkey_policy")) {
                    // Preserve the behavior of profiles created before host
                    // key verification became configurable.
                    profiles[i].add("hostkey_policy", Setting::TypeString) = "insecure";
                }
            }
        }
        log.event(INF, "added SSH upstream host-key policy");
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

    auto serialize = [](const Config& config, std::string& output) -> bool {
        char* data = nullptr;
        std::size_t size = 0;
        FILE* stream = ::open_memstream(&data, &size);
        if(stream == nullptr) return false;
        config.write(stream);
        const bool ok = ::fclose(stream) == 0;
        if(ok) output.assign(data, size);
        ::free(data);
        return ok;
    };


    auto backup = [this, &serialize](std::string const& prev_ver) {
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
            std::string content;
            if(!serialize(cfgapi, content)
               || sx::privsep::files::config_backup(CfgFactory::get()->config_file,
                                                     prev_ver, content) != 0) {
                throw FileIOException();
            }
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
    load_if_exists(cfgapi.getRoot()["settings"], "accept_http_connect", accept_http_connect);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_api", accept_api);
    bool configured_fail_open = false;
    policy_fail_open = cfgapi_detail::fail_open_setting(
        load_if_exists(cfgapi.getRoot()["settings"], "policy_fail_open",
                       configured_fail_open),
        configured_fail_open);
    configured_fail_open = false;
    policy_access_request_fail_open = cfgapi_detail::fail_open_setting(
        load_if_exists(cfgapi.getRoot()["settings"],
                       "policy_access_request_fail_open", configured_fail_open),
        configured_fail_open);
    auto& settings = cfgapi.getRoot()["settings"];
    auto load_listener_port = [&](char const* name, std::string& base,
                                  std::string& effective) {
        std::string candidate = base;
        const bool loaded = load_if_exists(settings, name, candidate);
        if((settings.exists(name) && !loaded) ||
           !sx::cfg::parse_transport_port(candidate)) {
            _err("load_settings: settings.%s has invalid transport port '%s'; keeping '%s'",
                 name, candidate.c_str(), base.c_str());
            Log::get()->events().insert(
                WAR, "CONFIG: settings.%s: invalid transport port '%s', keeping '%s'",
                name, candidate.c_str(), base.c_str());
            CfgFactory::LOAD_ERRORS = true;
            effective = base;
            return false;
        }
        base = candidate;
        effective = candidate;
        return true;
    };

    load_listener_port("plaintext_port", listen_tcp_port_base, listen_tcp_port);
    load_if_exists(cfgapi.getRoot()["settings"], "plaintext_workers",num_workers_tcp);
    load_listener_port("ssl_port", listen_tls_port_base, listen_tls_port);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_workers",num_workers_tls);
    load_listener_port("udp_port", listen_udp_port_base, listen_udp_port);
    load_if_exists(cfgapi.getRoot()["settings"], "udp_workers",num_workers_udp);
    load_listener_port("dtls_port", listen_dtls_port_base, listen_dtls_port);
    load_if_exists(cfgapi.getRoot()["settings"], "dtls_workers",num_workers_dtls);
    load_listener_port("quic_port", listen_quic_port_base, listen_quic_port);
    load_if_exists(cfgapi.getRoot()["settings"], "quic_workers",num_workers_quic);

    auto udp_redirect_port = sx::cfg::parse_transport_port(listen_udp_port, 973);
    if(!udp_redirect_port) {
        _err("load_settings: UDP port '%s' leaves no room for the DNS redirect offset",
             listen_udp_port.c_str());
        Log::get()->events().insert(
            WAR, "CONFIG: settings.udp_port: redirect offset exceeds 65535");
        CfgFactory::LOAD_ERRORS = true;
    }
    if(accept_redirect &&
       (!sx::cfg::parse_transport_port(listen_tcp_port, 1000) ||
        !sx::cfg::parse_transport_port(listen_tls_port, 1000) ||
        !udp_redirect_port)) {
        _err("load_settings: disabling redirect listeners with out-of-range derived ports");
        Log::get()->events().insert(
            WAR, "CONFIG: redirect listeners disabled: derived port exceeds 65535");
        CfgFactory::LOAD_ERRORS = true;
        accept_redirect = false;
    }

    bool collect_val = false;
    load_if_exists(cfgapi.getRoot()["settings"], "tpool_log", collect_val);
    sx::tp::ThreadPool::collect_tasks_info = collect_val;


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

            if(udp_redirect_port) {
                ReceiverRedirectMap::instance().map_add(
                    static_cast<int>(*udp_redirect_port) + 973,
                    ReceiverRedirectMap::redir_target_t(ns, 53));
            }
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

    load_listener_port("socks_port", listen_socks_port_base, listen_socks_port);
    load_if_exists(cfgapi.getRoot()["settings"], "socks_workers",num_workers_socks);
    load_listener_port("http_connect_port", listen_http_connect_port_base,
                       listen_http_connect_port);
    load_if_exists(cfgapi.getRoot()["settings"], "http_connect_workers",num_workers_http_connect);

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

    if(cfgapi.getRoot()["settings"].exists("tuning")) {
        auto const& tuning = cfgapi.getRoot()["settings"]["tuning"];
        if(tuning.exists("proxy_thread_spray_min")
           or tuning.exists("subproxy_thread_spray_bytes_min")) {
            _war("subproxy thread-spray tuning is deprecated and ignored; sub-proxies now run on their owning worker");
        }

        int hostcx_min = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_bufsz_min", hostcx_min);
        if(hostcx_min >= 1500 and hostcx_min < 10000000) { baseHostCX::params.buffsize = hostcx_min; } // maximum initial bufsize is guarded at 10MB

        int hostcx_maxmul = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_bufsz_max_multiplier", hostcx_maxmul);
        if(hostcx_maxmul > 0) { baseHostCX::params.buffsize_maxmul = hostcx_maxmul; }

        int hostcx_write_full = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_write_full", hostcx_write_full);
        if(hostcx_write_full >= 1024) { baseHostCX::params.write_full = hostcx_write_full; }

        int hostcx_io_batch = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_io_batch", hostcx_io_batch);
        if(hostcx_io_batch >= 16384) { baseHostCX::params.io_batch = hostcx_io_batch; }

        int tls_write_chunk = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "tls_write_chunk", tls_write_chunk);
        if(tls_write_chunk >= 1024 && tls_write_chunk <= 1048576) {
            SSLComOptions::write_chunk = static_cast<std::size_t>(tls_write_chunk);
        }

        int nbr_cache_size = 0;
        load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "nbr_cache_size", nbr_cache_size);
        if( nbr_cache_size > 0 and (static_cast<size_t>(nbr_cache_size) != NbrHood::instance().cache().capacity())) {
            NbrHood::instance().cache().set_capacity(static_cast<size_t>(nbr_cache_size));
        }

        if(int open_timeout = 0; load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_open_timeout", open_timeout)) {
            baseHostCX::params.open_timeout = open_timeout;
        }
        if(int idle_timeout = 0; load_if_exists(cfgapi.getRoot()["settings"]["tuning"], "host_idle_timeout", idle_timeout)) {
            baseHostCX::params.idle_delay = idle_timeout;
        }

    }

    if(cfgapi.getRoot()["settings"].exists("http_api")) {
        std::set<std::string> key_storage;

        if(cfgapi.getRoot()["settings"]["http_api"].exists("keys")) {
            const int num = cfgapi.getRoot()["settings"]["http_api"]["keys"].getLength();
            for (int i = 0; i < num; i++) {
                std::string key = cfgapi.getRoot()["settings"]["http_api"]["keys"][i];
                key_storage.emplace(key);
            }
        }
        sx::webserver::HttpSessions::replace_api_keys(std::move(key_storage));
        auto http_lock = std::scoped_lock(sx::webserver::HttpSessions::lock);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "key_timeout", sx::webserver::HttpSessions::session_ttl);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "key_extend_on_access", sx::webserver::HttpSessions::extend_on_access);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "loopback_only", sx::webserver::HttpSessions::loopback_only);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "bind_address", sx::webserver::HttpSessions::bind_address);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "bind_interface", sx::webserver::HttpSessions::bind_interface);
        load_if_exists(cfgapi.getRoot()["settings"]["http_api"], "allow_api_header", sx::webserver::HttpSessions::allow_api_header);

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
        } else {
            sx::webserver::HttpSessions::api_port = api_port;
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
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "ping_interval", settings_webhook.ping_interval);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "nbr_update_interval", settings_webhook.nbr_update_interval);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "nbr_tag_refresh_age", settings_webhook.nbr_tag_refresh_age);

        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "task_debug", sx::http::Request::DEBUG);
        load_if_exists(cfgapi.getRoot()["settings"]["webhook"], "task_debug_dump", sx::http::Request::DEBUG_DUMP_OK);

        sx::http::webhooks::set_hostid(settings_webhook.hostid);
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
            load_if_exists(remote, "gre_format", CfgFactory::get()->capture_remote.gre_format);
            if(CfgFactory::get()->capture_remote.gre_format == "spq1") {
                _war("GRE capture format 'spq1' is deprecated; use 'traffic'");
                CfgFactory::get()->capture_remote.gre_format = "traffic";
            }
            load_if_exists(remote, "tun_dst", CfgFactory::get()->capture_remote.tun_dst);
            load_if_exists(remote, "tun_ttl", CfgFactory::get()->capture_remote.tun_ttl);
            load_if_exists(remote, "bind_interface", CfgFactory::get()->capture_remote.bind_interface);

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

    auto valid_cidr = [](cidr::CIDR* value) {
        if(!value) return false;
        auto rendered = raw::allocated(cidr_to_str(value, CIDR_ONLYADDR));
        return rendered.value != nullptr && rendered.value[0] != '\0';
    };
    
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
                                if(valid_cidr(c)) {
                                    db_address[name] = std::make_shared<CfgAddress>(
                                            std::shared_ptr<AddressObject>(new CidrAddress(c)));
                                    db_address[name]->element_name() = name;
                                    _dia("cfgapi_load_addresses: cidr '%s': ok", name.c_str());
                                } else {
                                    if(c) cidr::cidr_free(c);
                                    _err("cfgapi_load_addresses: cidr '%s': invalid value '%s'",
                                         name.c_str(), address.c_str());
                                    Log::get()->events().insert(
                                        ERR, "CONFIG: address '%s': invalid CIDR '%s'",
                                        name.c_str(), address.c_str());
                                    CfgFactory::LOAD_ERRORS = true;
                                }
                            }
                            break;
                        case 1: // FQDN notation
                            if (load_if_exists(cur_object, "fqdn", address)) {
                                if(address.find_first_not_of(" \t\r\n") != std::string::npos) {
                                    db_address[name] = std::make_shared<CfgAddress>(
                                            std::shared_ptr<AddressObject>(new FqdnAddress(address)));
                                    db_address[name]->element_name() = name;
                                    _dia("cfgapi_load_addresses: fqdn '%s': ok", name.c_str());
                                } else {
                                    _err("cfgapi_load_addresses: fqdn '%s': empty value", name.c_str());
                                    Log::get()->events().insert(
                                        ERR, "CONFIG: address '%s': empty FQDN", name.c_str());
                                    CfgFactory::LOAD_ERRORS = true;
                                }
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
                        if(valid_cidr(c)) {
                            db_address[name] = std::make_shared<CfgAddress>(
                                    std::shared_ptr<AddressObject>(new CidrAddress(c)));
                            db_address[name]->element_name() = name;
                            _dia("cfgapi_load_addresses: cidr '%s': ok", name.c_str());
                        } else {
                            if(c) cidr::cidr_free(c);
                            _err("cfgapi_load_addresses: cidr '%s': invalid value '%s'",
                                 name.c_str(), address.c_str());
                            Log::get()->events().insert(
                                ERR, "CONFIG: address '%s': invalid CIDR '%s'",
                                name.c_str(), address.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
                    }
                }
                else if(type == "fqdn") {
                    if (load_if_exists(cur_object, "value", address)) {
                        if(address.find_first_not_of(" \t\r\n") != std::string::npos) {
                            db_address[name] = std::make_shared<CfgAddress>(
                                    std::shared_ptr<AddressObject>(new FqdnAddress(address)));
                            db_address[name]->element_name() = name;
                            _dia("cfgapi_load_addresses: fqdn '%s': ok", name.c_str());
                        } else {
                            _err("cfgapi_load_addresses: fqdn '%s': empty value", name.c_str());
                            Log::get()->events().insert(
                                ERR, "CONFIG: address '%s': empty FQDN", name.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                        }
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

                if(a < 0 or a > 65535 or b < 0 or b > 65535) {
                    _err("cfgapi_load_ports: '%s': values must be in 0..65535", name.c_str());
                    Log::get()->events().insert(WAR,
                        "CONFIG: port: '%s': range %d-%d is outside 0..65535",
                        name.c_str(), a, b);
                    CfgFactory::LOAD_ERRORS = true;
                    continue;
                }

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

                if(ia < 0 or ia > 255) {
                    _err("cfgapi_load_proto: '%s': id %d is outside 0..255",
                         name.c_str(), ia);
                    Log::get()->events().insert(
                        ERR, "CONFIG: proto '%s': id %d is outside 0..255",
                        name.c_str(), ia);
                    CfgFactory::LOAD_ERRORS = true;
                    continue;
                }

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

            std::string proto;
            std::string profile_detection;
            std::string profile_content;
            std::string action;
            std::string nat;
            
            bool soft_error = false;
            bool src_scope_error = false;
            bool sport_scope_error = false;
            bool dst_scope_error = false;
            bool dport_scope_error = false;

            _dia("cfgapi_load_policy: processing #%d", policy_index);
            
            auto rule = std::make_shared<PolicyRule>();

            auto load_policy_string = [&](const char* key, std::string& value) {
                if(!cur_object.exists(key)) return false;
                const Setting& setting = cur_object[key];
                if(setting.getType() != Setting::TypeString) {
                    _err("cfgapi_load_policy[#%d]: %s must be a string",
                         policy_index, key);
                    soft_error = true;
                    err_event(policy_index,
                              string_format("%s must be a string", key).c_str());
                    return false;
                }
                const char* configured = setting;
                value = configured ? configured : "";
                return true;
            };

            if(cur_object.exists("disabled")) {
                const Setting& setting = cur_object["disabled"];
                if(setting.getType() == Setting::TypeBoolean) {
                    rule->is_disabled = static_cast<bool>(setting);
                } else {
                    _err("cfgapi_load_policy[#%d]: disabled must be boolean", policy_index);
                    soft_error = true;
                    err_event(policy_index, "disabled must be boolean");
                }
            }

            load_if_exists(cur_object, "name", rule->policy_name);
            rule->element_name() = rule->policy_name.empty()
                ? string_format("policy-%d", policy_index)
                : rule->policy_name;

            if(load_policy_string("proto", proto)) {
                auto r = lookup_proto(proto.c_str());
                if(r) {
                    r->usage_add(std::weak_ptr(rule));
                    rule->proto = r;
                    _dia("cfgapi_load_policy[#%d]: proto object: %s", policy_index, proto.c_str());
                } else {
                    _dia("cfgapi_load_policy[#%d]: proto object not found: %s", policy_index, proto.c_str());
                    soft_error = true;

                    err_event(policy_index, string_format("proto object not found: '%s'", proto.c_str()).c_str());
                }
            } else {
                _err("cfgapi_load_policy[#%d]: required proto is missing", policy_index);
                soft_error = true;
                err_event(policy_index, "required proto is missing");
            }
            
            auto load_selector = [&]<typename Lookup, typename Container>(
                    const char* field, Lookup&& lookup, Container& destination,
                    bool& scope_error) {
                auto reject = [&](std::string_view detail) {
                    _err("cfgapi_load_policy[#%d]: %s", policy_index,
                         std::string(detail).c_str());
                    soft_error = true;
                    scope_error = true;
                    err_event(policy_index, std::string(detail).c_str());
                };

                if(!cur_object.exists(field)) {
                    reject(string_format("required %s selector is missing", field));
                    return;
                }

                const Setting& selector = cur_object[field];
                auto append = [&](const Setting& value) {
                    if(value.getType() != Setting::TypeString) {
                        reject(string_format("%s selector contains a non-string value", field));
                        return;
                    }
                    const char* object_name = value;
                    auto object = lookup(object_name);
                    if(!object) {
                        reject(string_format("%s object not found: '%s'", field, object_name));
                        return;
                    }
                    object->usage_add(std::weak_ptr(rule));
                    destination.emplace_back(std::move(object));
                };

                if(selector.isScalar()) {
                    append(selector);
                } else if(selector.isArray() || selector.isList()) {
                    for(int i = 0; i < selector.getLength(); ++i) append(selector[i]);
                } else {
                    reject(string_format("%s selector must be a string or list", field));
                }
            };

            load_selector("src", [this](const char* name) { return lookup_address(name); },
                          rule->src, src_scope_error);
            load_selector("sport", [this](const char* name) { return lookup_port(name); },
                          rule->src_ports, sport_scope_error);
            load_selector("dst", [this](const char* name) { return lookup_address(name); },
                          rule->dst, dst_scope_error);
            load_selector("dport", [this](const char* name) { return lookup_port(name); },
                          rule->dst_ports, dport_scope_error);

            // A missing selector is conservatively widened to a wildcard on
            // this already-DENY degraded rule.  Retaining only the valid
            // subset would still let the unknown part fall through.
            if(src_scope_error) rule->src.clear();
            if(sport_scope_error) rule->src_ports.clear();
            if(dst_scope_error) rule->dst.clear();
            if(dport_scope_error) rule->dst_ports.clear();

            if(cur_object.exists("features")) {
                const Setting &sett_features = cur_object["features"];
                if (sett_features.isArray() || sett_features.isList()) {
                    int sett_filters_count = sett_features.getLength();
                    _dia("cfgapi_load_policy[#%d]: features object list", policy_index);
                    for (int y = 0; y < sett_filters_count; y++) {
                        if(sett_features[y].getType() != Setting::TypeString) {
                            _err("cfgapi_load_policy[#%d]: features contains a non-string value",
                                 policy_index);
                            soft_error = true;
                            err_event(policy_index, "features contains a non-string value");
                            continue;
                        }
                        const char *obj_name = sett_features[y];

                        auto r = lookup_features(obj_name);
                        if (r) {
                            r->usage_add(std::weak_ptr(rule));
                            rule->features.emplace_back(r);
                            _dia("cfgapi_load_policy[#%d]: features object: %s", policy_index, obj_name);
                        } else {
                            _dia("cfgapi_load_policy[#%d]: features object not found: %s", policy_index, obj_name);
                            soft_error = true;

                            err_event(policy_index, string_format("features object not found: '%s'", obj_name).c_str());
                        }
                    }
                } else {
                    _err("cfgapi_load_policy[#%d]: features must be a list", policy_index);
                    soft_error = true;
                    war_event(policy_index, "features must be a list");
                }
            }
            
            if(load_policy_string("action", action)) {
                int r_a = PolicyRule::POLICY_ACTION_PASS;
                if(action == "deny" or action == "reject") {
                    _dia("cfgapi_load_policy[#%d]: action: deny", policy_index);
                    r_a = PolicyRule::POLICY_ACTION_DENY;
                    rule->action_name = "deny";

                } else if (action == "accept"){
                    _dia("cfgapi_load_policy[#%d]: action: accept", policy_index);
                    r_a = PolicyRule::POLICY_ACTION_PASS;
                    rule->action_name = action;
                } else {
                    _dia("cfgapi_load_policy[#%d]: action: unknown action '%s'", policy_index, action.c_str());
                    r_a  = PolicyRule::POLICY_ACTION_DENY;
                    soft_error = true;
                    war_event(policy_index, string_format("unknown action name: '%s'",action.c_str()).c_str());
                }
                
                rule->action = r_a;
            } else {
                rule->action = PolicyRule::POLICY_ACTION_DENY;
                rule->action_name = "deny";
            }

            if(load_policy_string("nat", nat)) {
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
                    soft_error = true;
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
                std::string name_ssh;
                std::string name_auth;
                std::string name_alg_dns;
                std::string name_script;
                std::string name_routing;

                if(load_policy_string("detection_profile", name_detection)) {
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
                
                if(load_policy_string("content_profile", name_content)) {
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
                if(load_policy_string("tls_profile", name_tls)) {
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
                if(load_policy_string("auth_profile", name_auth)) {
                    if(not name_auth.empty()) {
                        _err("cfgapi_load_policy[#%d]: auth_profile '%s' is no longer supported", policy_index, name_auth.c_str());
                        soft_error = true;
                        war_event(policy_index, string_format("auth_profile removed: '%s'", name_auth.c_str()).c_str());
                    }
                }
                if(load_policy_string("ssh_profile", name_ssh)) {
                    auto ssh = lookup_prof_ssh(name_ssh.c_str());
                    if(ssh) {
                        ssh->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: ssh profile %s",
                             policy_index, name_ssh.c_str());
                        rule->profile_ssh = ssh;
                    }
                    else if(!name_ssh.empty()) {
                        _err("cfgapi_load_policy[#%d]: ssh profile %s cannot be loaded",
                             policy_index, name_ssh.c_str());
                        soft_error = true;
                        war_event(policy_index,
                                  string_format("ssh_profile not loaded: '%s'",
                                                name_ssh.c_str()).c_str());
                    }
                }
                if(load_policy_string("alg_dns_profile", name_alg_dns)) {
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

                if(load_policy_string("script_profile", name_script)) {
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

                if(load_policy_string("routing", name_routing)) {

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


            if(soft_error) {
                _dia("cfgapi_load_policy[#%d]: enforcement error, forcing deny", policy_index);
                rule->cfg_err_is_degraded = true;
                rule->action = PolicyRule::POLICY_ACTION_DENY;
                rule->action_name = "deny";
            } else {
                _dia("cfgapi_load_policy[#%d]: ok", policy_index);
            }

            if(soft_error) LOAD_ERRORS = true;

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
        return policy_fail_open ? PolicyRule::POLICY_ACTION_PASS
                                : PolicyRule::POLICY_ACTION_DENY;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        auto const& rule = db_policy_list.at(index);
        if(rule->cfg_err_is_disabled or rule->cfg_err_is_degraded) {
            return PolicyRule::POLICY_ACTION_DENY;
        }
        return rule->action;
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
            
            if( load_if_exists(cur_object, "mode", new_prof->mode)
                and ProfileDetection::valid_mode(new_prof->mode) ) {

                new_prof->element_name() = name;
                const bool engines_valid =
                    !cur_object.exists("engines_enabled") ||
                    load_if_exists(cur_object, "engines_enabled",
                                   new_prof->engines_enabled);
                const bool kb_valid =
                    !cur_object.exists("kb_enabled") ||
                    load_if_exists(cur_object, "kb_enabled", new_prof->kb_enabled);
                if(!engines_valid || !kb_valid) {
                    _err("detection profile '%s': boolean option has an invalid type",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: detection_profile '%s': engines_enabled and kb_enabled must be boolean",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    continue;
                }

                db_prof_detection[name] =
                    std::shared_ptr<ProfileDetection>(std::move(new_prof));

                _dia("cfgapi_load_obj_profile_detect: '%s': ok", name.c_str());
            } else {
                _dia("cfgapi_load_obj_profile_detect: '%s': not ok", name.c_str());
                Log::get()->events().insert(
                    WAR,
                    "CONFIG: detection_profile '%s': missing or invalid 'mode' attribute",
                    cur_object.getName());
                CfgFactory::LOAD_ERRORS = true;

            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_prof_content_subrules(Setting& cur_object, ProfileContent* new_profile) {
    int jnum = cur_object["content_rules"].getLength();
    bool valid = true;
    _dia("replace rules in profile '%s', size %d", new_profile->element_name().c_str(), jnum);
    for (int j = 0; j < jnum; j++) {
        Setting &cur_replace_rule = cur_object["content_rules"][j];

        if(cur_replace_rule.getType() != Setting::TypeGroup) {
            _err("content profile '%s' rule %d is not an object",
                 new_profile->element_name().c_str(), j);
            Log::get()->events().insert(
                ERR, "CONFIG: content_profile[%s/%d]: rule is not an object",
                new_profile->element_name().c_str(), j);
            CfgFactory::LOAD_ERRORS = true;
            valid = false;
            continue;
        }

        std::string m;
        std::string r;
        bool action_defined = false;

        bool fill_length = false;
        int replace_each_nth = 0;

        auto load_rule_value = [&](const char* key, auto& destination) {
            if(!cur_replace_rule.exists(key)) return false;
            if(load_if_exists(cur_replace_rule, key, destination)) return true;
            _err("content profile '%s' rule %d: %s has an invalid type",
                 new_profile->element_name().c_str(), j, key);
            Log::get()->events().insert(
                ERR, "CONFIG: content_profile[%s/%d]: %s has an invalid type",
                new_profile->element_name().c_str(), j, key);
            CfgFactory::LOAD_ERRORS = true;
            valid = false;
            return false;
        };

        load_rule_value("match", m);
        const bool match_valid =
            cfgapi_detail::valid_content_rule_pattern(m);
        if(!m.empty() && !match_valid) {
            _err("content profile '%s' rule %d: match is not a valid regex",
                 new_profile->element_name().c_str(), j);
            Log::get()->events().insert(
                ERR, "CONFIG: content_profile[%s/%d]: invalid match regex",
                new_profile->element_name().c_str(), j);
            CfgFactory::LOAD_ERRORS = true;
            valid = false;
        }

        if (load_rule_value("replace", r)) {
            action_defined = true;
        }

        if(cur_replace_rule.exists("fill_length"))
            load_rule_value("fill_length", fill_length);
        if(cur_replace_rule.exists("replace_each_nth"))
            load_rule_value("replace_each_nth", replace_each_nth);

        if (match_valid && action_defined) {
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
            valid = false;
        }
    }

    return valid ? jnum : -1;
};


bool CfgFactory::load_db_prof_content_write_format(Setting& cur_object, ProfileContent* new_profile) {
    std::string write_format = "pcap_single";
    if(cur_object.exists("write_format") &&
       !load_if_exists(cur_object, "write_format", write_format)) {
        return false;
    }
    write_format = string_tolower(write_format);

    if(write_format != "smcap" && write_format != "pcap" &&
       write_format != "pcap_single") {
        return false;
    }

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
        bool valid = true;
        new_profile->element_name() = name;

        auto load_checked = [&]<typename T>(const char* key, T& destination) {
            if(!cur_object.exists(key)) return true;
            if(load_if_exists(cur_object, key, destination)) return true;
            _err("content profile '%s': %s has an invalid type",
                 name.c_str(), key);
            Log::get()->events().insert(
                ERR, "CONFIG: content_profile '%s': %s has an invalid type",
                name.c_str(), key);
            CfgFactory::LOAD_ERRORS = true;
            valid = false;
            return false;
        };

        if(cur_object.exists("write_payload") &&
           load_checked("write_payload", new_profile->write_payload)) {
            if(cur_object.exists("content_rules")) {
                auto& rules = cur_object["content_rules"];
                if((!rules.isArray() && !rules.isList()) ||
                   load_db_prof_content_subrules(cur_object, new_profile.get()) < 0) {
                    _err("content profile '%s': content_rules must be a list of objects",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR, "CONFIG: content_profile '%s': invalid content_rules collection",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
            }

            if(!load_db_prof_content_write_format(cur_object, new_profile.get())) {
                _err("content profile '%s': invalid write_format", name.c_str());
                Log::get()->events().insert(
                    ERR, "CONFIG: content_profile '%s': invalid write_format",
                    name.c_str());
                CfgFactory::LOAD_ERRORS = true;
                valid = false;
            }
        } else {
            _dia("load_db_prof_content: '%s': not ok", name.c_str());
            Log::get()->events().insert(ERR, "CONFIG: content_profile '%s': write_payload not specified", name.c_str());
            CfgFactory::LOAD_ERRORS = true;
            valid = false;
        }

        load_checked("webhook_enable", new_profile->webhook_enable);
        load_checked("webhook_lock_traffic", new_profile->webhook_lock_traffic);
        load_checked("ja4_tls_ch", new_profile->ja4_tls_ch);
        load_checked("ja4_tls_ch_ignore_sni", new_profile->ja4_tls_ch_ignore_sni);

        load_checked("ja4_tls_sh", new_profile->ja4_tls_sh);
        // I's quite costy (2x dynamic casts) to set this per-connection.
        // Because we normally don't store TLS ServerHello, we globally enable ServerHello
        // collection (only) if ANY content profile turns it on!
        load_checked("ja4_http", new_profile->ja4_http);

        if(cur_object.exists("rules_session_filter") &&
           load_checked("rules_session_filter", new_profile->rules_session_filter)) {
            if(not new_profile->rules_session_filter.empty()) {
                if(not new_profile->create_rule_session_filter_rx()) {
                    _war("load_db_prof_content: '%s': rules_session_filter not loaded", name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: content_profile '%s': invalid rules_session_filter",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
            }
        }

        if(valid) {
            db_prof_content[name] = new_profile;
            if(new_profile->ja4_tls_sh) {
                SSLComOptions::server_hello_copy = true;
            }
            _dia("load_db_prof_content: '%s': ok", name.c_str());
        } else {
            _dia("load_db_prof_content: '%s': rejected", name.c_str());
        }
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
            bool valid = true;

            auto load_checked = [&]<typename T>(const char* key, T& destination) {
                if(!cur_object.exists(key)) return true;
                if(load_if_exists(cur_object, key, destination)) return true;
                _err("TLS profile '%s': %s has an invalid type", name.c_str(), key);
                Log::get()->events().insert(
                    ERR, "CONFIG: tls_profile '%s': %s has an invalid type",
                    name.c_str(), key);
                CfgFactory::LOAD_ERRORS = true;
                valid = false;
                return false;
            };

            _dia("load_db_prof_tls: processing '%s'", name.c_str());
            
            if(cur_object.exists("inspect") &&
               load_checked("inspect", new_profile->inspect)) {

                new_profile->element_name() = name;
                load_checked("no_fallback_bypass", new_profile->no_fallback_bypass);
                load_checked("client_hello_timeout", new_profile->client_hello_timeout);
                load_checked("handshake_timeout", new_profile->handshake_timeout);
                if(new_profile->client_hello_timeout <= 0) {
                    _err("TLS profile '%s': client_hello_timeout must be positive",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: tls_profile '%s': client_hello_timeout must be positive",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                if(new_profile->handshake_timeout <= 0) {
                    _err("TLS profile '%s': handshake_timeout must be positive",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: tls_profile '%s': handshake_timeout must be positive",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }

                load_checked("allow_untrusted_issuers", new_profile->allow_untrusted_issuers);
                load_checked("allow_invalid_certs", new_profile->allow_invalid_certs);
                load_checked("allow_self_signed", new_profile->allow_self_signed);
                cfgapi_detail::load_pfs_options(*new_profile,
                    [&](const char* option, bool& value) {
                        load_checked(option, value);
                    });
                load_checked("left_disable_reuse", new_profile->left_disable_reuse);
                load_checked("right_disable_reuse", new_profile->right_disable_reuse);

                load_checked("ocsp_mode", new_profile->ocsp_mode);
                load_checked("ocsp_stapling", new_profile->ocsp_stapling);
                load_checked("ocsp_stapling_mode", new_profile->ocsp_stapling_mode);
                if(!ProfileTls::valid_revocation_mode(new_profile->ocsp_mode) ||
                   !ProfileTls::valid_revocation_mode(new_profile->ocsp_stapling_mode)) {
                    _err("TLS profile '%s': OCSP modes must be in range 0..2",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: tls_profile '%s': ocsp_mode and ocsp_stapling_mode must be in range 0..2",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                load_checked("ct_enable", new_profile->opt_ct_enable);
                load_checked("alpn_block", new_profile->opt_alpn_block);
                load_checked("failed_certcheck_replacement", new_profile->failed_certcheck_replacement);
                load_checked("failed_certcheck_override", new_profile->failed_certcheck_override);
                load_checked("failed_certcheck_override_timeout", new_profile->failed_certcheck_override_timeout);
                load_checked("failed_certcheck_override_timeout_type", new_profile->failed_certcheck_override_timeout_type);
                if(new_profile->failed_certcheck_override_timeout <= 0 ||
                   (new_profile->failed_certcheck_override_timeout_type != 0 &&
                    new_profile->failed_certcheck_override_timeout_type != 1)) {
                    _err("TLS profile '%s': invalid certificate override timeout or mode",
                         name.c_str());
                    Log::get()->events().insert(
                        ERR,
                        "CONFIG: tls_profile '%s': override timeout must be positive and mode must be 0 or 1",
                        name.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                if(cur_object.exists("client_cert_action")) {
                    auto& action = cur_object["client_cert_action"];
                    if(action.getType() == Setting::TypeString) {
                        std::string const configured = static_cast<const char*>(action);
                        new_profile->client_cert_action =
                            ProfileTls::client_cert_action_value(configured);
                        if(ProfileTls::client_cert_action_name(new_profile->client_cert_action) !=
                           configured) {
                            _err("TLS profile '%s': invalid client_cert_action '%s'",
                                 name.c_str(), configured.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                            valid = false;
                        }
                    } else if(action.getType() == Setting::TypeInt) {
                        int const legacy_action = action;
                        new_profile->client_cert_action =
                            ProfileTls::normalized_client_cert_action(legacy_action);
                        if(new_profile->client_cert_action != legacy_action) {
                            _err("TLS profile '%s': invalid legacy client_cert_action %d",
                                 name.c_str(), legacy_action);
                            CfgFactory::LOAD_ERRORS = true;
                            valid = false;
                        }
                    } else {
                        _err("TLS profile '%s': invalid client_cert_action type",
                             name.c_str());
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;
                    }
                }
                load_checked("sni_based_cert", new_profile->mitm_cert_sni_search);
                load_checked("ip_based_cert", new_profile->mitm_cert_ip_search);
                load_checked("only_custom_certs", new_profile->mitm_cert_searched_only);

                if(cur_object.exists("sni_filter_bypass")) {
                        Setting& sni_filter = cur_object["sni_filter_bypass"];
                        if(!sni_filter.isArray() && !sni_filter.isList()) {
                            _err("TLS profile '%s': sni_filter_bypass must be a list",
                                 name.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                            valid = false;
                        } else if(int const sni_filter_len = sni_filter.getLength();
                                  sni_filter_len > 0) {
                                new_profile->sni_filter_bypass = std::make_shared<std::vector<std::string>>();
                                new_profile->sni_filter_bypass_addrobj = std::make_shared<std::vector<FqdnAddress>>();

                                for(int j = 0; j < sni_filter_len; ++j) {
                                    if(sni_filter[j].getType() != Setting::TypeString) {
                                        _err("TLS profile '%s': sni_filter_bypass[%d] must be a string",
                                             name.c_str(), j);
                                        CfgFactory::LOAD_ERRORS = true;
                                        valid = false;
                                        continue;
                                    }
                                    const char* elem = sni_filter[j];
                                    new_profile->sni_filter_bypass->push_back(elem);
                                    new_profile->sni_filter_bypass_addrobj->emplace_back(elem);
                                }
                        }
                }
                load_checked("sni_filter_use_dns_cache",
                             new_profile->sni_filter_use_dns_cache);
                load_checked("sni_filter_use_dns_domain_tree",
                             new_profile->sni_filter_use_dns_domain_tree);
                

                if(cur_object.exists("redirect_warning_ports")) {
                        Setting& rwp = cur_object["redirect_warning_ports"];
                        if(!rwp.isArray() && !rwp.isList()) {
                            _err("TLS profile '%s': redirect_warning_ports must be a list",
                                 name.c_str());
                            CfgFactory::LOAD_ERRORS = true;
                            valid = false;
                        } else if(int const rwp_len = rwp.getLength(); rwp_len > 0) {
                                new_profile->redirect_warning_ports.ptr(new std::set<int>);
                                for(int j = 0; j < rwp_len; ++j) {
                                    if(rwp[j].getType() != Setting::TypeInt) {
                                        _err("TLS profile '%s': redirect_warning_ports[%d] must be an integer",
                                             name.c_str(), j);
                                        CfgFactory::LOAD_ERRORS = true;
                                        valid = false;
                                        continue;
                                    }
                                    int elem = rwp[j];
                                    if(elem < 0 || elem > 65535) {
                                        _err("TLS profile '%s': redirect warning port %d is outside 0..65535",
                                             name.c_str(), elem);
                                        CfgFactory::LOAD_ERRORS = true;
                                        valid = false;
                                        continue;
                                    }
                                    new_profile->redirect_warning_ports.ptr()->insert(elem);
                                }
                        }
                }
                load_checked("sslkeylog", new_profile->sslkeylog);

                std::string alertval;
                if(load_checked("alerts", alertval)) {
                    if(cur_object.exists("alerts")) {
                    if (alertval == "all") {
                        new_profile->alerts.suppress_common = false;
                        new_profile->alerts.suppress_all = false;
                    }
                    else if (alertval == "unusual") {
                        new_profile->alerts.suppress_common = true;
                        new_profile->alerts.suppress_all = false;
                    }
                    else if (alertval == "mute" ) {
                        new_profile->alerts.suppress_common = true;
                        new_profile->alerts.suppress_all = true;
                    } else {
                        _err("TLS profile '%s': alerts must be all, unusual, or mute",
                             name.c_str());
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;
                    }
                    }
                }

                if(valid) {
                    db_prof_tls[name] = new_profile;
                    _dia("load_db_prof_tls: '%s': ok", name.c_str());
                } else {
                    _dia("load_db_prof_tls: '%s': rejected", name.c_str());
                }
            } else {
                _dia("load_db_prof_tls: '%s': not ok", name.c_str());
            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_prof_ssh () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    int num = 0;
    if (!cfgapi.getRoot().exists("ssh_profiles")) {
        return num;
    }

    Setting& profiles = cfgapi.getRoot()["ssh_profiles"];
    num = profiles.getLength();
    for (int i = 0; i < num; ++i) {
        Setting& item = profiles[i];
        if (!item.getName()) continue;

        std::string const name = item.getName();
        if (name.rfind("__", 0) == 0) continue;

        auto profile = std::make_shared<ProfileSsh>();
        profile->element_name() = name;
        if (!load_if_exists(item, "host_key", profile->host_key)
            || profile->host_key.empty()) {
            _err("load_db_prof_ssh: '%s': host_key not specified", name.c_str());
            Log::get()->events().insert(
                ERR, "CONFIG: ssh_profile '%s': host_key not specified", name.c_str());
            LOAD_ERRORS = true;
            continue;
        }
        if(item.exists("hostkey_policy") &&
           !load_if_exists(item, "hostkey_policy", profile->hostkey_policy)) {
            _err("load_db_prof_ssh: '%s': hostkey_policy has an invalid type",
                 name.c_str());
            Log::get()->events().insert(
                ERR, "CONFIG: ssh_profile '%s': hostkey_policy has an invalid type",
                name.c_str());
            LOAD_ERRORS = true;
            continue;
        }
        profile->hostkey_policy = string_tolower(profile->hostkey_policy);
        if(profile->hostkey_policy != "insecure"
           && profile->hostkey_policy != "accept-new"
           && profile->hostkey_policy != "strict") {
            _err("load_db_prof_ssh: '%s': invalid hostkey_policy '%s'",
                 name.c_str(), profile->hostkey_policy.c_str());
            Log::get()->events().insert(
                ERR, "CONFIG: ssh_profile '%s': hostkey_policy must be insecure, accept-new, or strict",
                name.c_str());
            LOAD_ERRORS = true;
            continue;
        }

        bool valid = true;
        auto load_action = [&](char const* key, bool& destination) {
            std::string action = "pass";
            if(item.exists(key) && !load_if_exists(item, key, action)) {
                _err("load_db_prof_ssh: '%s': %s has an invalid type",
                     name.c_str(), key);
                Log::get()->events().insert(
                    ERR, "CONFIG: ssh_profile '%s': %s has an invalid type",
                    name.c_str(), key);
                LOAD_ERRORS = true;
                valid = false;
                return;
            }
            action = string_tolower(action);
            if(action == "pass") {
                destination = true;
            } else if(action == "reject") {
                destination = false;
            } else {
                _err("load_db_prof_ssh: '%s': invalid %s action '%s'",
                     name.c_str(), key, action.c_str());
                Log::get()->events().insert(
                    ERR, "CONFIG: ssh_profile '%s': %s must be pass or reject",
                    name.c_str(), key);
                LOAD_ERRORS = true;
                valid = false;
            }
        };
        load_action("shell", profile->shell);
        load_action("exec", profile->exec);
        load_action("subsystem", profile->subsystem);
        load_action("pty", profile->pty);
        load_action("environment", profile->environment);
        load_action("local_forward", profile->local_forward);
        load_action("remote_forward", profile->remote_forward);
        load_action("x11", profile->x11);
        load_action("agent", profile->agent);

        if(valid) {
            db_prof_ssh[name] = profile;
            _dia("load_db_prof_ssh: '%s': ok", name.c_str());
        } else {
            _dia("load_db_prof_ssh: '%s': rejected", name.c_str());
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
            bool valid = true;
            auto load_checked = [&](const char* key, bool& destination) {
                if(!cur_object.exists(key)) return;
                if(load_if_exists(cur_object, key, destination)) return;
                _err("DNS ALG profile '%s': %s has an invalid type",
                     name.c_str(), key);
                Log::get()->events().insert(
                    ERR, "CONFIG: alg_dns_profile '%s': %s has an invalid type",
                    name.c_str(), key);
                CfgFactory::LOAD_ERRORS = true;
                valid = false;
            };
            load_checked("match_request_id", new_prof->match_request_id);
            load_checked("randomize_id", new_prof->randomize_id);
            load_checked("cached_responses", new_prof->cached_responses);

            if(valid)
                db_prof_alg_dns[name] =
                    std::shared_ptr<ProfileAlgDns>(std::move(new_prof));
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

    if(cfgapi.getRoot()["settings"].exists("auth_portal")) {
        _war("settings.auth_portal is obsolete and ignored; the legacy captive-auth backend was removed");
    }

    _dia("load_db_prof_auth: profiles");
    if(cfgapi.getRoot().exists("auth_profiles")) {
        _war("auth_profiles is obsolete; entries are retained only for configuration compatibility");

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

size_t CfgFactory::cleanup_db_prof_ssh () {
    std::scoped_lock<std::recursive_mutex> l(lock_);

    auto const result = db_prof_ssh.size();
    db_prof_ssh.clear();
    return result;
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


bool CfgFactory::prof_content_apply (baseHostCX *originator, MitmProxy *mitm_proxy, const std::shared_ptr<ProfileContent> &pc) {

    auto const& log = log::policy();

    bool ret = true;
    bool cfg_wrt;

    if(mitm_proxy != nullptr) {
        if(pc != nullptr) {
            const auto pc_name = cfgapi_detail::profile_name_or(pc);
            _dia("policy_apply: policy content profile[%s]: write payload: %d", pc_name.c_str(), pc->write_payload);

            mitm_proxy->writer_opts()->write_payload = pc->write_payload;
            mitm_proxy->writer_opts()->webhook_enable = pc->webhook_enable;
            mitm_proxy->writer_opts()->webhook_lock_traffic = pc->webhook_lock_traffic;

            mitm_proxy->acct_opts.ja4_clienthello = pc->ja4_tls_ch;
            mitm_proxy->acct_opts.ja4_clienthello_ignore_sni = pc->ja4_tls_ch_ignore_sni;
            mitm_proxy->acct_opts.ja4_serverhello = pc->ja4_tls_sh;
            auto* mh = MitmHostCX::from_baseHostCX(originator);
            if(mh) {
                cfgapi_detail::apply_ja4_http_option(
                    pc->ja4_http,
                    mitm_proxy->acct_opts,
                    mh->engine_ctx.options.http);
            } else {
                mitm_proxy->acct_opts.ja4_http = pc->ja4_http;
            }

            bool filter_ok = true;
            if(pc->rules_session_filter_rx.has_value()) {
                try {
                    auto px_name = mitm_proxy->to_string(iINF);
                    filter_ok = std::regex_search(px_name, pc->rules_session_filter_rx.value());
                    _deb("policy_apply: policy content profile[%s]: rules_session_filter - session name: '%s'", pc_name.c_str(), px_name.c_str());
                    _deb("policy_apply: policy content profile[%s]: rules_session_filter - session filter: '%s'", pc_name.c_str(), pc->rules_session_filter.c_str());
                    _dia("policy_apply: policy content profile[%s]: rules_session_filter - %s", pc_name.c_str(), filter_ok ? "matched" : "skipping");
                }
                catch(std::regex_error const& e) {
                    _dia("policy_apply: policy content profile[%s]: rules_session_filter error: %s", pc_name.c_str(), e.what());
                }
            }

            if( ! pc->content_rules.empty() and filter_ok ) {
                _dia("policy_apply: policy content profile[%s]: applying content rules, size %d", pc_name.c_str(), pc->content_rules.size());
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


bool CfgFactory::prof_detect_apply (baseHostCX *originator, MitmProxy *mitm_proxy, const std::shared_ptr<ProfileDetection> &pd) {

    auto* mitm_originator = dynamic_cast<MitmHostCX*>(originator);
    auto const& log = log::policy();

    std::string pd_name = "none";
    bool ret = true;
    
    // we scan connection on client's side
    if(mitm_originator != nullptr) {
        mitm_originator->mode(AppHostCX::mode_t::NONE);
        if(pd != nullptr)  {
            pd_name = cfgapi_detail::profile_name_or(pd);
            _dia("policy_apply[%s]: policy detection profile: mode: %d", pd_name.c_str(), pd->mode);
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

bool CfgFactory::prof_tls_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileTls> &ps) {

    auto const& log = log::policy();

    if(not new_proxy or not originator) {
        _err("CfgFactory::prof_tls_apply: proxy or originator is null");
        return false;
    }

    if(not ps) {
        _err("CfgFactory::prof_tls_apply[%s]: profile is null", new_proxy->to_string(iINF).c_str());
        return false;
    }

    if(not cfgapi_detail::dns_sni_bypass_state_complete(ps)) {
        _err("CfgFactory::prof_tls_apply: incomplete DNS-backed SNI bypass state");
        return false;
    }

    bool tls_applied = false;

    if( not policy_apply_tls(ps, originator->com())) {
        _err("CfgFactory::prof_tls_apply[%s]: cannot apply on originator cx", new_proxy->to_string(iINF).c_str());
        return false;
    }



    _dia("CfgFactory::prof_tls_apply[%s]: profile %s, originator %s", new_proxy->to_string(iINF).c_str(), ps->element_name().c_str(), originator->full_name('L').c_str());

    for( auto* cx: new_proxy->rs()) {
        if(not cx or not cx->com()) {
            _err("CfgFactory::prof_tls_apply[%s]: target context is incomplete",
                 new_proxy->to_string(iINF).c_str());
            return false;
        }
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

bool CfgFactory::prof_alg_dns_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileAlgDns> &p_alg_dns) {

    auto const& log = log::policy();

    auto* mh = dynamic_cast<MitmHostCX*>(originator);

    bool ret = false;
    
    if(mh != nullptr) {

        if(p_alg_dns != nullptr) {
            if(DNS_Inspector::dns_prefilter(mh)) {
                auto* n = new DNS_Inspector();

                _dia("policy_apply: policy dns profile[%s] for %s", p_alg_dns->element_name().c_str(), mh->full_name('L').c_str());
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


bool CfgFactory::prof_script_apply (baseHostCX *originator, MitmProxy *new_proxy, std::shared_ptr<ProfileScript> const& p_script) {

    auto const& log = log::policy();

    auto* mh = dynamic_cast<MitmHostCX*>(originator);

    bool ret = false;

    if(mh != nullptr) {

        if(p_script) {

            _dia("policy_apply: policy script profile[%s] for %s", p_script->element_name().c_str(), mh->full_name('L').c_str());

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
                    access_filter = new AccessFilter(
                        mitm_proxy, policy_access_request_fail_open);
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

int CfgFactory::policy_apply (baseHostCX *originator, MitmProxy *proxy, int matched_policy) {

    auto const& log = log::policy();

    auto lc_ = std::scoped_lock(lock_);

    if(not originator or not proxy) {
        _err("policy_apply: missing originator or proxy");
        return -1;
    }

    int policy_num = sx::policy::preserve_explicit_match(
        matched_policy, [&] { return policy_match(proxy); });
    if(policy_num < 0 and policy_fail_open) {
        _war("Connection %s accepted without a policy match: settings.policy_fail_open=true",
             originator->full_name('L').c_str());
        return PolicyRule::POLICY_IMPLICIT_PASS;
    }
    if(auto verdict = policy_action(policy_num); verdict == PolicyRule::POLICY_ACTION_PASS) {
        auto rule = policy_rule(policy_num);
        if(not rule) {
            _err("policy_apply: matched policy %d disappeared before application", policy_num);
            return -1;
        }

        auto pc = policy_prof_content(policy_num);
        auto pd = policy_prof_detection(policy_num);
        auto pt = policy_prof_tls(policy_num);
        auto pa = policy_prof_auth(policy_num);
        auto p_alg_dns = policy_prof_alg_dns(policy_num);
        auto p_script = policy_prof_script(policy_num);


        std::string pc_name = cfgapi_detail::profile_name_or(pc);
        std::string pd_name = cfgapi_detail::profile_name_or(pd);
        std::string pt_name = cfgapi_detail::profile_name_or(pt);
        std::string pa_name = cfgapi_detail::profile_name_or(pa);

        //Algs will be list of single letter abbreviations
        // DNS alg: D
        std::string algs_name;

        /* Processing content profile */
        if (pc) {
            if (not prof_content_apply(originator, proxy, pc)) {
                _err("policy_apply: configured content profile failed");
                return -1;
            }
        }
        
        
        /* Processing detection profile */
        if (pd and not prof_detect_apply(originator, proxy, pd)) {
            _err("policy_apply: configured detection profile failed");
            return -1;
        }
        
        /* Processing TLS profile*/
        if (pt and not prof_tls_apply(originator, proxy, pt)) {
            _err("policy_apply: configured TLS profile failed");
            return -1;
        }

        /* Processing script profile */
        if (p_script and not prof_script_apply(originator, proxy, p_script)) {
            _err("policy_apply: configured script profile failed");
            return -1;
        }

        if (rule && rule->profile_ssh) {
#ifdef USE_LIBSSH
            // SOCKS applies the selected policy to both host contexts of the
            // same proxy. Staging is therefore intentionally idempotent.
            if (!proxy->stream_handler()) {
                xdia(sx::ssh::transport_log())(
                    "staging SSH stream handler for %s using profile='%s'",
                    originator->full_name('L').c_str(),
                    rule->profile_ssh->element_name().c_str());
                auto options = sx::ssh::transport_options{};
                options.profile_name = rule->profile_ssh->element_name();
                options.host_key = rule->profile_ssh->host_key;
                options.hostkeys = rule->profile_ssh->hostkey_policy == "strict"
                    ? sx::ssh::hostkey_policy::strict
                    : rule->profile_ssh->hostkey_policy == "accept-new"
                        ? sx::ssh::hostkey_policy::accept_new
                        : sx::ssh::hostkey_policy::insecure;
                options.features.shell = rule->profile_ssh->shell;
                options.features.exec = rule->profile_ssh->exec;
                options.features.subsystem = rule->profile_ssh->subsystem;
                options.features.pty = rule->profile_ssh->pty;
                options.features.environment = rule->profile_ssh->environment;
                options.features.local_forward = rule->profile_ssh->local_forward;
                options.features.remote_forward = rule->profile_ssh->remote_forward;
                options.features.x11 = rule->profile_ssh->x11;
                options.features.agent = rule->profile_ssh->agent;
                if (!proxy->stage_stream_handler(
                        std::make_unique<sx::ssh::stream_handler>(std::move(options)))) {
                    _err("Connection %s: cannot stage SSH stream handler",
                         originator->full_name('L').c_str());
                    return -1;
                }
            }
            else {
                xdeb(sx::ssh::transport_log())(
                    "SSH stream handler already staged for %s",
                    originator->full_name('L').c_str());
            }
#else
            _err("Connection %s: SSH profile requested but libssh support is not built",
                 originator->full_name('L').c_str());
            return -1;
#endif
        }
        
        /* Processing ALG : DNS*/
        if (p_alg_dns and prof_alg_dns_apply(originator, proxy, p_alg_dns)) {
            algs_name += p_alg_dns->element_name();
        }

        auto* mitm_proxy = dynamic_cast<MitmProxy*>(proxy);
        if(mitm_proxy) {

            /* Processing Features */
            policy_apply_features(rule, mitm_proxy);
            if(mitm_proxy->state().dead()) {
                _inf("Connection %s rejected by policy feature during initialization",
                     originator->full_name('L').c_str());
                return -1;
            }
        }
        
        // ALGS can operate only on MitmHostCX classes

        
        _inf("Connection %s accepted: policy=%d cont=%s det=%s tls=%s auth=%s algs=%s", originator->full_name('L').c_str(), policy_num, pc_name.c_str(), pd_name.c_str(), pt_name.c_str(), pa_name.c_str(), algs_name.c_str());

    } else {
        _inf("Connection %s denied: policy=%d", originator->full_name('L').c_str(), policy_num);
        return -1;
    }
    
    return policy_num;
}


void CfgFactory::gre_export_apply(traflog::PcapLog* pcaplog) {

    auto const& log = CfgFactoryBase::log::config();
    auto const& cfg = CfgFactory::get();

    if(cfg->capture_remote.enabled) {
        if(not cfg->capture_remote.tun_dst.empty()) {
            auto c = CidrAddress(cfg->capture_remote.tun_dst);

            auto ip = c.ip();
            auto fam = c.cidr()->proto;

            auto exp = std::make_shared<traflog::GreExporter>(fam, ip);

            // Select either the legacy IP-packet hook or serialized PCAPNG
            // records here, without exposing QUIC to the capture abstractions.
            if(cfg->capture_remote.gre_format == "pcapng") {
                exp->format(traflog::GreExporter::payload_format::pcapng_record);
                pcaplog->ip_packet_hook.reset();
                pcaplog->pcapng_record_hook = exp;
            } else {
                if(cfg->capture_remote.gre_format != "traffic") {
                    _war("unknown GRE capture format '%s', using traffic",
                         cfg->capture_remote.gre_format.c_str());
                }
                exp->origin(pcap::connection_details::record_origin::synthetic);
                pcaplog->pcapng_record_hook.reset();
                pcaplog->ip_packet_hook = exp;
            }

            if(cfg->capture_remote.tun_ttl > 0) {
                exp->ttl(cfg->capture_remote.tun_ttl);
            }
            if(not cfg->capture_remote.bind_interface.empty()) {
                exp->bind_if(cfg->capture_remote.bind_interface);
            }

        } else {
            pcaplog->ip_packet_hook.reset();
            pcaplog->pcapng_record_hook.reset();
        }
    } else {
        pcaplog->ip_packet_hook.reset();
        pcaplog->pcapng_record_hook.reset();
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

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_port();
                  return CfgFactory::get()->load_db_port(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("proto_objects") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_proto();
                  return CfgFactory::get()->load_db_proto(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("address_objects") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_address();
                  return CfgFactory::get()->load_db_address(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("detection_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_detection();
                  return CfgFactory::get()->load_db_prof_detection(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("content_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_content();
                  return CfgFactory::get()->load_db_prof_content(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("tls_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_tls();
                  return CfgFactory::get()->load_db_prof_tls(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("ssh_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_ssh();
                  return CfgFactory::get()->load_db_prof_ssh(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("alg_dns_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_alg_dns();
                  return CfgFactory::get()->load_db_prof_alg_dns(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("script_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_script();
                  return CfgFactory::get()->load_db_prof_script(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    } else
    if( 0 == section.find("auth_profiles") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_prof_auth();
                  return CfgFactory::get()->load_db_prof_auth(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
    }
    else
    if( 0 == section.find("routing") ) {

        ret = cfgapi_detail::reload_policy_dependency(
            [] { CfgFactory::get()->cleanup_db_routing();
                  return CfgFactory::get()->load_db_routing(); },
            [] { CfgFactory::get()->cleanup_db_policy();
                  return CfgFactory::get()->load_db_policy(); });
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

    if(not cfgapi_detail::replacement_redirect_state_complete(pt, com)) {
        _err("should_redirect: incomplete TLS replacement state");
        return false;
    }
    
    bool ret = false;
    
    _deb("should_redirect[%s]", com->hr().c_str());
    
    if(com && com->owner_cx()) {

        if(com->owner_cx()->port().empty()) {
            _deb("should_redirect[%s]: unknown cx port", com->hr().c_str());
            return false;
        }

        if(auto const num_port = cfgapi_detail::parse_transport_port(
               com->owner_cx()->port()); num_port) {
            _deb("should_redirect[%s]: owner port %d", com->hr().c_str(), *num_port);
            ret = cfgapi_detail::replacement_redirect_port_matches(
                com->owner_cx()->port(), pt->redirect_warning_ports.ptr());
            if(ret)
                _dia("should_redirect[%s]: port %d allowed to be redirected if needed",
                     com->hr().c_str(), *num_port);
        } else {
            _err("should_redirect[%s]: invalid owner port '%s'",
                 com->hr().c_str(), com->owner_cx()->port().c_str());
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
        sslcom->opt.client_hello_timeout = pt->client_hello_timeout;
        sslcom->opt.handshake_timeout = pt->handshake_timeout;

        sslcom->opt.cert.allow_unknown_issuer = pt->allow_untrusted_issuers;
        sslcom->opt.cert.allow_self_signed_chain = pt->allow_untrusted_issuers;
        sslcom->opt.cert.allow_not_valid = pt->allow_invalid_certs;
        sslcom->opt.cert.allow_self_signed = pt->allow_self_signed;

        sslcom->opt.cert.failed_check_replacement = pt->failed_certcheck_replacement;
        sslcom->opt.cert.failed_check_override = pt->failed_certcheck_override;
        sslcom->opt.cert.failed_check_override_timeout = pt->failed_certcheck_override_timeout;
        sslcom->opt.cert.failed_check_override_timeout_type = pt->failed_certcheck_override_timeout_type;
        sslcom->opt.cert.client_cert_action = pt->client_cert_action;
        sslcom->opt.cert.mitm_cert_sni_search = pt->mitm_cert_sni_search;
        sslcom->opt.cert.mitm_cert_ip_search = pt->mitm_cert_ip_search;
        sslcom->opt.cert.mitm_cert_searched_only = pt->mitm_cert_searched_only;

        auto* peer_sslcom = dynamic_cast<SSLCom*>(sslcom->peer());

        const bool peer_port_eligible = peer_sslcom && should_redirect(pt, peer_sslcom);
        const bool peer_replacement = peer_sslcom &&
            pt->failed_certcheck_replacement && peer_port_eligible;
        if(peer_sslcom) {
            // This function is also used when TLS policy is reapplied after a
            // protocol transition.  Replacement is complete profile state:
            // an ineligible or disabled new profile must retire the peer's
            // earlier value rather than leaving it armed.
            cfgapi_detail::replace_peer_replacement_state(
                peer_sslcom->opt.cert, pt->failed_certcheck_replacement,
                peer_port_eligible);
        }

        if(peer_replacement) {

            _deb("policy_apply_tls: applying profile, repl=%d, repl_ovrd=%d, repl_ovrd_tmo=%d, repl_ovrd_tmo_type=%d, sni_search=%d, ip_search=%d, custom_only=%d",
                 pt->failed_certcheck_replacement,
                 pt->failed_certcheck_override,
                 pt->failed_certcheck_override_timeout,
                 pt->failed_certcheck_override_timeout_type,
                 pt->mitm_cert_sni_search,
                 pt->mitm_cert_ip_search,
                 pt->mitm_cert_searched_only);

            peer_sslcom->opt.cert.failed_check_override = pt->failed_certcheck_override;
            peer_sslcom->opt.cert.failed_check_override_timeout = pt->failed_certcheck_override_timeout;
            peer_sslcom->opt.cert.failed_check_override_timeout_type = pt->failed_certcheck_override_timeout_type;
            peer_sslcom->opt.cert.client_cert_action = pt->client_cert_action;
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

        cfgapi_detail::replace_sni_bypass_filter(
            sslcom->sni_filter_to_bypass(), pt->sni_filter_bypass);

        sslcom->sslkeylog = pt->sslkeylog;

        sslcom->opt.alerts.suppress_all = pt->alerts.suppress_all;
        sslcom->opt.alerts.decode_error_in_operational = not pt->alerts.suppress_common; // target is inclusion flag

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
    cleanup_db_prof_ssh();
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
    auto const port = cfgapi_detail::offset_transport_port(what, idx);
    if(!port) {
        _err("cannot apply tenant index %u to transport port '%s'", idx, what.c_str());
        return -1;
    }
    what = std::to_string(*port);

    return 0;
}


bool CfgFactory::apply_tenant_config () {
    int ret = 0;

    if(not tenant_name.empty()) {
        ret += apply_tenant_index(listen_tcp_port, tenant_index);
        ret += apply_tenant_index(listen_tls_port, tenant_index);
        ret += apply_tenant_index(listen_dtls_port, tenant_index);
        ret += apply_tenant_index(listen_quic_port, tenant_index);
        ret += apply_tenant_index(listen_udp_port, tenant_index);
        ret += apply_tenant_index(listen_socks_port, tenant_index);
        ret += apply_tenant_index(listen_http_connect_port, tenant_index);
        auto const cli_port = cfgapi_detail::offset_transport_port(
            std::to_string(CfgFactory::get()->cli_port), tenant_index);
        if(cli_port) CfgFactory::get()->cli_port = *cli_port;
        else ret -= 1;
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
                char* addr = cidr_to_str(cidr_ptr->cidr());
                if (addr) {
                    s_cidr = addr;
                    ::free(addr);
                }
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
            bool valid = true;

            if(cur_object.exists("dnat_address")) {
                auto& da = cur_object["dnat_address"];
                if(!da.isArray() && !da.isList()) {
                    _err("load_db_routing[%d]: dnat_address is not a list", i);
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                const auto da_l = (da.isArray() || da.isList())
                    ? da.getLength() : 0;
                for (int j = 0; j < da_l; ++j) {
                    if(da[j].getType() != Setting::TypeString) {
                        _err("load_db_routing[%d]: dnat_address[%d] is not a string", i, j);
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;
                        continue;
                    }
                    const char* address = da[j];
                    if(db_address.find(address) == db_address.end()) {
                        _dia("load_db_routing[%d]: unknown dnat address: '%s'", i, address);
                        Log::get()->events().insert(WAR,"CONFIG: routing_profile[%s]: dnat_address: address '%s' unknown", name.c_str(), address);
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;

                        continue;
                    }
                    new_profile->dnat_addresses.emplace_back(address);
                }
            }


            if(cur_object.exists("dnat_port")) {
                auto& dp = cur_object["dnat_port"];
                if(!dp.isArray() && !dp.isList()) {
                    _err("load_db_routing[%d]: dnat_port is not a list", i);
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                const auto dp_l = (dp.isArray() || dp.isList())
                    ? dp.getLength() : 0;
                for (int j = 0; j < dp_l; ++j) {
                    if(dp[j].getType() != Setting::TypeString) {
                        _err("load_db_routing[%d]: dnat_port[%d] is not a string", i, j);
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;
                        continue;
                    }
                    const char* port = dp[j];
                    if(db_port.find(port) == db_port.end()) {
                        _dia("load_db_routing[%d]: unknown dnat port: '%s'", i, port);
                        Log::get()->events().insert(WAR,"CONFIG: routing_profile[%s]: dnat_port: port '%s' unknown", name.c_str(), port);
                        CfgFactory::LOAD_ERRORS = true;
                        valid = false;


                        continue;
                    }
                    new_profile->dnat_ports.emplace_back(port);
                }
            }

            std::string lb_meth;
            if(cur_object.exists("dnat_lb_method")) {
                if(!load_if_exists(cur_object, "dnat_lb_method", lb_meth)) {
                    _err("load_db_routing[%d]: dnat_lb_method has an invalid type", i);
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                } else {
                auto const method = ProfileRouting::parse_lb_method(lb_meth);
                if(method) {
                    new_profile->dnat_lb_method = *method;
                } else {
                    _err("load_db_routing[%d]: invalid load-balancing method '%s'",
                         i, lb_meth.c_str());
                    Log::get()->events().insert(
                        WAR,
                        "CONFIG: routing_profile[%s]: invalid dnat_lb_method '%s'",
                        name.c_str(), lb_meth.c_str());
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
                }
            }

            for(auto const* key: {"rewrite_sni", "rewrite_sni_to"}) {
                auto& destination = std::string_view(key) == "rewrite_sni"
                    ? new_profile->rewrite_sni : new_profile->rewrite_sni_to;
                if(cur_object.exists(key) &&
                   !load_if_exists(cur_object, key, destination)) {
                    _err("load_db_routing[%d]: %s has an invalid type", i, key);
                    CfgFactory::LOAD_ERRORS = true;
                    valid = false;
                }
            }

            if(!ProfileRouting::valid_sni_rewrite_pair(
                    new_profile->rewrite_sni, new_profile->rewrite_sni_to)) {
                _err("load_db_routing[%d]: rewrite_sni and rewrite_sni_to must be configured together",
                     i);
                Log::get()->events().insert(
                    WAR,
                    "CONFIG: routing_profile[%s]: rewrite_sni and rewrite_sni_to must be configured together",
                    name.c_str());
                CfgFactory::LOAD_ERRORS = true;
                valid = false;
            }

            if(!valid) {
                _err("load_db_routing[%d]: profile '%s' rejected", i, name.c_str());
                continue;
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

        routing_item.add("rewrite_sni", Setting::TypeString) = obj->rewrite_sni;
        routing_item.add("rewrite_sni_to", Setting::TypeString) = obj->rewrite_sni_to;

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
        item.add("rewrite_sni", Setting::TypeString) = "";
        item.add("rewrite_sni_to", Setting::TypeString) = "";
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
        item.add("ja4_tls_ch", Setting::TypeBoolean) = obj->ja4_tls_ch;
        item.add("ja4_tls_ch_ignore_sni", Setting::TypeBoolean) = obj->ja4_tls_ch_ignore_sni;
        item.add("ja4_tls_sh", Setting::TypeBoolean) = obj->ja4_tls_sh;
        item.add("ja4_http", Setting::TypeBoolean) = obj->ja4_http;
        item.add("rules_session_filter", Setting::TypeString) = obj->rules_session_filter;

        if(! obj->content_rules.empty() ) {

            Setting& cr_rules = item.add("content_rules", Setting::TypeList);

            for(auto const& cr: obj->content_rules) {
                Setting& cr_rule = cr_rules.add(Setting::TypeGroup);
                cfgapi_detail::save_content_rule(cr_rule, cr);
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
        item.add("client_hello_timeout", Setting::TypeInt) = 3000;
        item.add("handshake_timeout", Setting::TypeInt) = 10000;

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
        item.add("alpn_block", Setting::TypeBoolean) = false;

        // add sni bypass list
        item.add("sni_filter_bypass", Setting::TypeArray);
        item.add("sni_filter_use_dns_cache", Setting::TypeBoolean) = true;
        item.add("sni_filter_use_dns_domain_tree", Setting::TypeBoolean) = true;
        item.add("redirect_warning_ports", Setting::TypeArray);

        item.add("failed_certcheck_replacement", Setting::TypeBoolean) = true;
        item.add("failed_certcheck_override", Setting::TypeBoolean) = false;
        item.add("failed_certcheck_override_timeout", Setting::TypeInt) = 600;
        item.add("failed_certcheck_override_timeout_type", Setting::TypeInt) = 0;
        item.add("client_cert_action", Setting::TypeString) = "use_configured";
        item.add("sni_based_cert", Setting::TypeBoolean) = true;
        item.add("ip_based_cert", Setting::TypeBoolean) = true;
        item.add("only_custom_certs", Setting::TypeBoolean) = false;


        item.add("left_disable_reuse", Setting::TypeBoolean) = false;
        item.add("right_disable_reuse", Setting::TypeBoolean) = false;
        item.add("sslkeylog", Setting::TypeBoolean) = false;
        item.add("alerts", Setting::TypeString) = "all";
    }
    catch(libconfig::SettingException const& e) {
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
        item.add("client_hello_timeout", Setting::TypeInt) = obj->client_hello_timeout;
        item.add("handshake_timeout", Setting::TypeInt) = obj->handshake_timeout;

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
        item.add("sni_filter_use_dns_cache", Setting::TypeBoolean) =
            obj->sni_filter_use_dns_cache;
        item.add("sni_filter_use_dns_domain_tree", Setting::TypeBoolean) =
            obj->sni_filter_use_dns_domain_tree;

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
        item.add("client_cert_action", Setting::TypeString) =
            ProfileTls::client_cert_action_name(obj->client_cert_action).data();
        item.add("sni_based_cert", Setting::TypeBoolean) = obj->mitm_cert_sni_search;
        item.add("ip_based_cert", Setting::TypeBoolean) = obj->mitm_cert_ip_search;
        item.add("only_custom_certs", Setting::TypeBoolean) = obj->mitm_cert_searched_only;


        item.add("left_disable_reuse", Setting::TypeBoolean) = obj->left_disable_reuse;
        item.add("right_disable_reuse", Setting::TypeBoolean) = obj->right_disable_reuse;
        item.add("sslkeylog", Setting::TypeBoolean) = obj->sslkeylog;


        if(obj->alerts.suppress_all) {
            item.add("alerts", Setting::TypeString) = "mute";
        }
        else if(obj->alerts.suppress_common) {
            item.add("alerts", Setting::TypeString) = "unusual";
        }
        else {
            item.add("alerts", Setting::TypeString) = "all";
        }

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
        newpol.add("ssh_profile", Setting::TypeString);
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
    (void)iobufsz;
    return cfgapi_detail::write_config_crlf(cfg, where);
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
    else if(section == "ssh_profiles") {
        if (CfgFactory::get()->new_ssh_profile(s, entry_name)) {
            added = true;
            CfgFactory::get()->load_db_prof_ssh();
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

    if(added && cfgapi_detail::policy_dependency_section(section)) {
        // A rule which referenced this previously missing object was loaded
        // as a fail-closed degraded rule. Rebuild it now so live policy
        // reflects the dependency which the CLI has just created.
        CfgFactory::get()->cleanup_db_policy();
        CfgFactory::get()->load_db_policy();
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
    return sx::cfg::parse_number<int>(v);
}

std::optional<long long int> make_lli(std::string const& v) {
    return sx::cfg::parse_number<long long int>(v);
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
    return sx::cfg::parse_number<float>(v);
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
                    } else if(sx::cfg::integer_array_path(setting.getPath())) {
                        // libconfig does not retain an element type for an
                        // empty array, so recover the two numeric schema paths.
                        first_elem_type = Setting::TypeInt;
                    }

                    std::vector<std::string> consolidated_values;
                    for(auto const &v: values) {
                        auto arg_values = string_split(v, ',');

                        for (auto const &av: arg_values)
                            consolidated_values.push_back(av);
                    }

                    // Validate and normalize the complete replacement before
                    // removing any element from the live array.
                    std::vector<std::string> checked_values;
                    checked_values.reserve(consolidated_values.size());
                    for(auto const& i: consolidated_values) {

                        auto [ verdict, msg ]  = CfgValueHelp::get().value_check(setting.getPath(), i);

                        if(not verdict) {
                            ret_verdict = false;
                            ret_msg = msg;
                            break;
                        }
                        checked_values.push_back(*verdict);
                    }

                    if(ret_verdict) {
                        for(auto const& value : checked_values) {
                            bool convertible = false;
                            switch(first_elem_type) {
                                case Setting::TypeInt:
                                    convertible = make_int(value).has_value();
                                    break;
                                case Setting::TypeInt64:
                                    convertible = make_lli(value).has_value();
                                    break;
                                case Setting::TypeBoolean:
                                    convertible = make_bool(value).has_value();
                                    break;
                                case Setting::TypeFloat:
                                    convertible = make_float(value).has_value();
                                    break;
                                case Setting::TypeString:
                                    convertible = true;
                                    break;
                                default:
                                    break;
                            }
                            if(!convertible) {
                                ret_verdict = false;
                                ret_msg = "invalid value conversion";
                                break;
                            }
                        }
                    }

                    if(ret_verdict) {
                        if (not checked_values.empty() or no_args_erases_array) {

                            // ugly (but only) way to remove
                            for (int x = setting.getLength() - 1; x >= 0; x--) {
                                setting.remove(x);
                            }

                            for(auto const& cons_val: checked_values) {
                                if(!write_value(setting, cons_val, first_elem_type)) {
                                    ret_verdict = false;
                                    break;
                                }
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

        item.add("action", Setting::TypeString) =
            std::string(cfgapi_detail::policy_action_for_save(*pol));
        item.add("nat", Setting::TypeString) = pol->nat_name;

        if(pol->profile_routing)
            item.add("routing", Setting::TypeString) = pol->profile_routing->element_name();
        else
            item.add("routing", Setting::TypeString) = "none";

        if(pol->profile_tls)
            item.add("tls_profile", Setting::TypeString) = pol->profile_tls->element_name();
        item.add("ssh_profile", Setting::TypeString) =
            pol->profile_ssh ? pol->profile_ssh->element_name() : "";
        if(pol->profile_detection)
            item.add("detection_profile", Setting::TypeString) = pol->profile_detection->element_name();
        if(pol->profile_content)
            item.add("content_profile", Setting::TypeString) = pol->profile_content->element_name();
        if(pol->profile_auth)
            item.add("auth_profile", Setting::TypeString) = pol->profile_auth->element_name();
        if(pol->profile_alg_dns)
            item.add("alg_dns_profile", Setting::TypeString) = pol->profile_alg_dns->element_name();
        if(pol->profile_script)
            item.add("script_profile", Setting::TypeString) = pol->profile_script->element_name();

        n_saved++;
    }

    return n_saved;
}

bool CfgFactory::new_ssh_profile(Setting& section, std::string const& name) const {
    try {
        Setting& item = section.add(name, Setting::TypeGroup);
        item.add("host_key", Setting::TypeString) = "/etc/smithproxy/ssh_host_ed25519_key";
        item.add("hostkey_policy", Setting::TypeString) = "accept-new";
        for(auto const* feature : {"shell", "exec", "subsystem", "pty",
                                   "environment", "local_forward",
                                   "remote_forward", "x11", "agent"}) {
            item.add(feature, Setting::TypeString) = "pass";
        }
        return true;
    }
    catch(libconfig::SettingException const& e) {
        _war("cannot add new SSH profile %s: %s", name.c_str(), e.what());
        return false;
    }
}

int CfgFactory::save_ssh_profiles(Config& ex) const {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());
    Setting& profiles = ex.getRoot().add("ssh_profiles", Setting::TypeGroup);

    int saved = 0;
    for (auto const& [name, element]: db_prof_ssh) {
        auto profile = std::dynamic_pointer_cast<ProfileSsh>(element);
        if (!profile) continue;

        Setting& item = profiles.add(name, Setting::TypeGroup);
        item.add("host_key", Setting::TypeString) = profile->host_key;
        item.add("hostkey_policy", Setting::TypeString) = profile->hostkey_policy;
        auto save_action = [&](char const* key, bool pass) {
            item.add(key, Setting::TypeString) = pass ? "pass" : "reject";
        };
        save_action("shell", profile->shell);
        save_action("exec", profile->exec);
        save_action("subsystem", profile->subsystem);
        save_action("pty", profile->pty);
        save_action("environment", profile->environment);
        save_action("local_forward", profile->local_forward);
        save_action("remote_forward", profile->remote_forward);
        save_action("x11", profile->x11);
        save_action("agent", profile->agent);
        ++saved;
    }
    return saved;
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
    objects.add("accept_http_connect", Setting::TypeBoolean) = CfgFactory::get()->accept_http_connect;
    objects.add("policy_fail_open", Setting::TypeBoolean) = CfgFactory::get()->policy_fail_open;
    objects.add("policy_access_request_fail_open", Setting::TypeBoolean) = CfgFactory::get()->policy_access_request_fail_open;

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

    objects.add("quic_port", Setting::TypeString) = CfgFactory::get()->listen_quic_port_base;
    objects.add("quic_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_quic;

    objects.add("tpool_log", Setting::TypeBoolean) = sx::tp::ThreadPool::collect_tasks_info;

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
    objects.add("http_connect_port", Setting::TypeString) = CfgFactory::get()->listen_http_connect_port_base;
    objects.add("http_connect_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_http_connect;

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

    Setting& tuning_objects = objects.add("tuning", Setting::TypeGroup);
    tuning_objects.add("host_bufsz_min", Setting::TypeInt) = (int) baseHostCX::params.buffsize;
    tuning_objects.add("host_bufsz_max_multiplier", Setting::TypeInt) = (int) baseHostCX::params.buffsize_maxmul;
    tuning_objects.add("host_write_full", Setting::TypeInt) = (int) baseHostCX::params.write_full;
    tuning_objects.add("host_io_batch", Setting::TypeInt) = (int) baseHostCX::params.io_batch;
    tuning_objects.add("tls_write_chunk", Setting::TypeInt) = (int) SSLComOptions::write_chunk.load();
    tuning_objects.add("host_open_timeout", Setting::TypeInt) = (unsigned short) baseHostCX::params.open_timeout;
    tuning_objects.add("host_idle_timeout", Setting::TypeInt) = (unsigned short) baseHostCX::params.idle_delay;
    tuning_objects.add("nbr_cache_size", Setting::TypeInt) = (int) NbrHood::instance().cache().capacity();


    objects.add("accept_api", Setting::TypeBoolean) = CfgFactory::get()->accept_api;
    Setting& http_api_objects = objects.add("http_api", Setting::TypeGroup);

    Setting& keys = http_api_objects.add("keys", Setting::TypeArray);
    for(auto const& k: sx::webserver::HttpSessions::api_keys_snapshot()) {
        keys.add(Setting::TypeString) = k;
    }
    auto http_lock = std::scoped_lock(sx::webserver::HttpSessions::lock);
    http_api_objects.add("key_timeout", Setting::TypeInt) = (int)sx::webserver::HttpSessions::session_ttl;
    http_api_objects.add("key_extend_on_access", Setting::TypeBoolean) = (bool)sx::webserver::HttpSessions::extend_on_access;
    http_api_objects.add("loopback_only", Setting::TypeBoolean) = (bool)sx::webserver::HttpSessions::loopback_only;
    http_api_objects.add("bind_address", Setting::TypeString) = sx::webserver::HttpSessions::bind_address;
    http_api_objects.add("bind_interface", Setting::TypeString) = sx::webserver::HttpSessions::bind_interface;
    http_api_objects.add("allow_api_header", Setting::TypeBoolean) = sx::webserver::HttpSessions::allow_api_header;

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
    webhook_objects.add("ping_interval", Setting::TypeInt) = (int)CfgFactory::get()->settings_webhook.ping_interval;
    webhook_objects.add("nbr_update_interval", Setting::TypeInt) = CfgFactory::get()->settings_webhook.nbr_update_interval;
    webhook_objects.add("nbr_tag_refresh_age", Setting::TypeInt) = CfgFactory::get()->settings_webhook.nbr_tag_refresh_age;

    webhook_objects.add("task_debug", Setting::TypeBoolean) = sx::http::Request::DEBUG;
    webhook_objects.add("task_debug_dump", Setting::TypeBoolean) = sx::http::Request::DEBUG_DUMP_OK;

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
    remote.add("gre_format", Setting::TypeString) = CfgFactory::get()->capture_remote.gre_format;
    remote.add("tun_dst", Setting::TypeString) = CfgFactory::get()->capture_remote.tun_dst;
    remote.add("tun_ttl", Setting::TypeInt) = CfgFactory::get()->capture_remote.tun_ttl;
    remote.add("bind_interface", Setting::TypeString) = CfgFactory::get()->capture_remote.bind_interface;


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

    n = save_ssh_profiles(ex);
    _inf("%d ssh_profiles", n);

    n = save_alg_dns_profiles(ex);
    _inf("%d alg_dns_profiles", n);

    {
        Setting& profiles = ex.getRoot().add("script_profiles", Setting::TypeGroup);
        n = 0;
        for(auto const& [name, element]: db_prof_script) {
            auto profile = std::dynamic_pointer_cast<ProfileScript>(element);
            if(!profile) continue;
            Setting& item = profiles.add(name, Setting::TypeGroup);
            item.add("type", Setting::TypeInt) = profile->script_type;
            item.add("script-file", Setting::TypeString) = profile->module_path;
            ++n;
        }
    }
    _inf("%d script_profiles", n);

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
        char* data = nullptr;
        std::size_t size = 0;
        FILE* stream = ::open_memstream(&data, &size);
        if(stream == nullptr) throw FileIOException();
        ex.write(stream);
        const bool serialized = ::fclose(stream) == 0;
        std::string content;
        if(serialized) content.assign(data, size);
        ::free(data);
        if(!serialized || sx::privsep::files::config_write(CfgFactory::get()->config_file,
                                                           content) != 0) {
            throw FileIOException();
        }
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
    static thread_local AddressInfo selected;
    auto lock = std::scoped_lock(CfgFactory::lock());
    auto const& db = CfgFactory::get()->db_nameservers;
    if (not db.empty()) {

        if(pref_family != 0) for(auto const& can: db) {
                if(can.family == pref_family) {
                    selected = can;
                    return selected;
                }
            }
        selected = db.at(0);
        return selected;
    }
    selected = default_ns();
    return selected;
}


AddressInfo DNS_Setup::create_default_ns(int fam, const char* ip, unsigned short port) {
    AddressInfo ai;
    ai.str_host = ip;
    ai.port = port;
    ai.family = fam;
    ai.pack();

    return ai;
}
