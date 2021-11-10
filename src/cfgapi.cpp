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
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <vector>

#include <socle.hpp>
#include <main.hpp>


#include <cfgapi.hpp>
#include <service/cmd/cmdserver.hpp>
#include <service/cmd/clistate.hpp>
#include <log/logger.hpp>

#include <policy/policy.hpp>
#include <policy/authfactory.hpp>
#include <inspect/sigfactory.hpp>
#include <inspect/sxsignature.hpp>

#include <proxy/mitmproxy.hpp>
#include <proxy/mitmhost.hpp>

#include <inspect/dnsinspector.hpp>
#include <inspect/pyinspector.hpp>

CfgFactory::CfgFactory(): CfgFactoryBase() , args_debug_flag(NON), syslog_level(INF) {

    listen_tcp_port = "50080";
    listen_tls_port = "50443";
    listen_dtls_port = "50443";
    listen_udp_port = "50080";
    listen_socks_port = "1080";

    listen_tcp_port_base = "50080";
    listen_tls_port_base = "50443";
    listen_dtls_port_base = "50443";
    listen_udp_port_base = "50080";
    listen_socks_port_base = "1080";

    config_file_check_only = false;

    dir_msg_templates = "/etc/smithproxy/msg/en/";


    num_workers_tcp = 0;
    num_workers_tls = 0;
    num_workers_dtls = 0;
    num_workers_udp = 0;
    num_workers_socks = 0;

    syslog_server = "";
    syslog_port = 514;
    syslog_facility = 23; //local7
    syslog_family = 4;


    // multi-tenancy support
    tenant_name = "default";
    tenant_index = 0;


    traflog_dir = "/var/local/smithproxy/data";
    //traflog_file_prefix = "";
    traflog_file_suffix = "pcapng";

    log_console = false;
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
    throw std::logic_error(msg.c_str());
}

bool CfgFactory::cfgapi_init(const char* fnm) {
    
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    _dia("Reading config file");
    
    // Read the file. If there is an error, report it and exit.
    try {
        cfgapi.readFile(fnm);
    }
    catch(const FileIOException &fioex)
    {
        _err("I/O error while reading config file: %s", fnm);
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_address.find(name) != db_address.end()) {
        return std::dynamic_pointer_cast<CfgAddress>(db_address[name]);
    }
    
    return nullptr;
}

std::shared_ptr<CfgRange> CfgFactory::lookup_port (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_port.find(name) != db_port.end()) {
        return std::dynamic_pointer_cast<CfgRange>(db_port[name]);
    }    
    
    return std::make_shared<CfgRange>(NULLRANGE);
}

std::shared_ptr<CfgUint8> CfgFactory::lookup_proto (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_proto.find(name) != db_proto.end()) {
        return std::dynamic_pointer_cast<CfgUint8>(db_proto[name]);
    }    
    
    return std::make_shared<CfgUint8>(0);
}

std::shared_ptr<ProfileContent> CfgFactory::lookup_prof_content (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_prof_content.find(name) != db_prof_content.end()) {
        return std::dynamic_pointer_cast<ProfileContent>(db_prof_content[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileDetection> CfgFactory::lookup_prof_detection (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_prof_detection.find(name) != db_prof_detection.end()) {
        return std::dynamic_pointer_cast<ProfileDetection>(db_prof_detection[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileTls> CfgFactory::lookup_prof_tls (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_prof_tls.find(name) != db_prof_tls.end()) {
        return std::dynamic_pointer_cast<ProfileTls>(db_prof_tls[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileAlgDns> CfgFactory::lookup_prof_alg_dns (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_prof_alg_dns.find(name) != db_prof_alg_dns.end()) {
        return std::dynamic_pointer_cast<ProfileAlgDns>(db_prof_alg_dns[name]);
    }    
    
    return nullptr;

}

std::shared_ptr<ProfileScript> CfgFactory::lookup_prof_script(const char * name)  {
    std::lock_guard<std::recursive_mutex> l(lock_);

    if(db_prof_script.find(name) != db_prof_script.end()) {
        return std::dynamic_pointer_cast<ProfileScript>(db_prof_script[name]);
    }

    return nullptr;

}

std::shared_ptr<ProfileAuth> CfgFactory::lookup_prof_auth (const char *name) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(db_prof_auth.find(name) != db_prof_auth.end()) {
        return std::dynamic_pointer_cast<ProfileAuth>(db_prof_auth[name]);
    }    
    
    return nullptr;
}

std::shared_ptr<ProfileRouting> CfgFactory::lookup_prof_routing(const char * name)  {
    std::lock_guard<std::recursive_mutex> l(lock_);

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

bool CfgFactory::upgrade(std::string const& from) {

    std::cout << "upgrade check: " << from << " -> " << SMITH_VERSION  << std::endl;

    if(version_compare(SMITH_VERSION, "0.9.23").value_or(-1) > 0) {
        return upgrade_to_0_9_23();
    }

    return false;
}

bool CfgFactory::upgrade_to_0_9_23 () {

    std::cout << "upgrade script to 0.9.23" << std::endl;

    long long tmp;
    if(load_if_exists(CfgFactory::cfg_root()["settings"], "write_pcap_single_quota", tmp)) {
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
            _err("cannot upgrade config file");
            return false;
        }
        return true;
    };

    if(not cfgapi.getRoot().exists("*_internal_*")) {

        // versioning first initialization

        cfgapi.getRoot().add("*_internal_*", Setting::TypeGroup);

        auto& internal = cfgapi.getRoot()["*_internal_*"];
        auto& v = internal.add("version", Setting::TypeString);
        v = SMITH_VERSION;

        return save_status();

    }

    auto& internal = cfgapi.getRoot()["*_internal_*"];


    bool do_save = false;
    std::string v1;
    if(load_if_exists(internal, "version", v1)) {

        if (v1 != SMITH_VERSION) {
            backup(v1);
            upgrade(v1);

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

    std::lock_guard<std::recursive_mutex> l(lock_);

    if (!cfgapi.getRoot().exists("*_internal_*"))
        return false;

    return load_if_exists(cfgapi.getRoot()["*_internal_*"], "version", internal_version);
}


bool CfgFactory::load_settings () {

    std::lock_guard<std::recursive_mutex> l(lock_);

    if(! cfgapi.getRoot().exists("settings"))
        return false;

    load_if_exists(cfgapi.getRoot()["settings"], "accept_tproxy", accept_tproxy);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_redirect", accept_redirect);
    load_if_exists(cfgapi.getRoot()["settings"], "accept_socks", accept_socks);
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
            db_nameservers.push_back(ns);

            ReceiverRedirectMap::instance().map_add(std::stoi(listen_udp_port) + 973, ReceiverRedirectMap::redir_target_t(ns, 53));  // to make default port 51053 suggesting DNS
        }
    }

    load_if_exists(cfgapi.getRoot()["settings"], "certs_path",SSLFactory::certs_path());
    load_if_exists(cfgapi.getRoot()["settings"], "certs_ca_key_password",SSLFactory::certs_password());

    if(! load_if_exists(cfgapi.getRoot()["settings"], "certs_ctlog",SSLFactory::ctlogfile())) {
        SSLFactory::ctlogfile() = "/etc/smithproxy/ct_log_list.cnf";
    }


    if(! load_if_exists(cfgapi.getRoot()["settings"], "ca_bundle_path",SSLFactory::ca_path())) {
        load_if_exists(cfgapi.getRoot()["settings"], "certs_ca_path", SSLFactory::ca_path());
    }

    load_if_exists(cfgapi.getRoot()["settings"], "ssl_autodetect",MitmMasterProxy::ssl_autodetect);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_autodetect_harder",MitmMasterProxy::ssl_autodetect_harder);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_ocsp_status_ttl",SSLFactory::ssl_ocsp_status_ttl);
    load_if_exists(cfgapi.getRoot()["settings"], "ssl_crl_status_ttl",SSLFactory::ssl_crl_status_ttl);

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
        }
    }

    load_if_exists(cfgapi.getRoot()["settings"], "log_level", CfgFactory::get()->internal_init_level.level_ref());

    load_if_exists(cfgapi.getRoot()["settings"], "syslog_server", syslog_server);
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_port", syslog_port);
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_facility", syslog_facility);
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_level", syslog_level.level_ref());
    load_if_exists(cfgapi.getRoot()["settings"], "syslog_family", syslog_family);

    load_if_exists(cfgapi.getRoot()["settings"], "messages_dir", dir_msg_templates);

    if(cfgapi.getRoot()["settings"].exists("cli")) {
        load_if_exists<int>(cfgapi.getRoot()["settings"]["cli"], "port", CliState::get().cli_port_base);
        CliState::get().cli_port = CliState::get().cli_port_base;

        load_if_exists(cfgapi.getRoot()["settings"]["cli"], "enable_password", CliState::get().cli_enable_password);
    }

    if(cfgapi.getRoot()["settings"].exists("auth_portal")) {
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "address", auth_address);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "http_port", auth_http);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "https_port", auth_https);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "ssl_key", auth_sslkey);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "ssl_cert", auth_sslcert);
        load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "magic_ip", tenant_magic_ip);
    }

    load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_dir", CfgFactory::get()->traflog_dir);
    load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_file_prefix", CfgFactory::get()->traflog_file_prefix);
    load_if_exists(CfgFactory::cfg_root()["settings"], "write_payload_file_suffix", CfgFactory::get()->traflog_file_suffix);

    int quota_megabytes;
    load_if_exists(CfgFactory::cfg_root()["settings"], "write_pcap_single_quota", quota_megabytes);
    traflog::PcapLog::single_instance().stat_bytes_quota = quota_megabytes*1024*1024;

    return true;
}


int CfgFactory::load_debug() {

    std::lock_guard<std::recursive_mutex> l(lock_);

    if(! cfgapi.getRoot().exists("debug")) {

        load_if_exists(CfgFactory::cfg_root()["debug"], "log_data_crc", baseCom::debug_log_data_crc);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_sockets", baseHostCX::socket_in_name);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_online_cx_name", baseHostCX::online_name);
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_srclines", Log::get()->print_srcline());
        load_if_exists(CfgFactory::cfg_root()["debug"], "log_srclines_always", Log::get()->print_srcline_always());

        if (cfgapi.getRoot()["debug"].exists("log")) {

            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "sslcom", SSLCom::log_level_ref().level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "sslmitmcom",
                                                               baseSSLMitmCom<SSLCom>::log_level_ref().level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "sslmitmcom",
                                                               baseSSLMitmCom<DTLSCom>::log_level_ref().level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "sslcertstore",
                                                               SSLFactory::get_log().level()->level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "proxy", baseProxy::log_level_ref().level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "proxy", epoll::log_level.level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "mtrace", cfg_mtrace_enable);
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "openssl_mem_dbg", cfg_openssl_mem_dbg);

            /*DNS ALG EXPLICIT LOG*/
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "alg_dns", DNS_Inspector::log_level_ref().level_ref());
            load_if_exists(CfgFactory::cfg_root()["debug"]["log"], "alg_dns", DNS_Packet::log_level_ref().level_ref());
        }
        return 1;
    }

    return -1;
}

int CfgFactory::load_db_address () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int num = 0;
    
    _dia("cfgapi_load_addresses: start");
    
    if(cfgapi.getRoot().exists("address_objects")) {

        num = cfgapi.getRoot()["address_objects"].getLength();
        _dia("cfgapi_load_addresses: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["address_objects"];

        for( int i = 0; i < num; i++) {
            std::string name;
            std::string address;
            int type;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_address: unnamed object index %d: not ok", i);
                continue;
            }
            
            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _deb("cfgapi_load_addresses: processing '%s'", name.c_str());
            
            if( load_if_exists(cur_object, "type", type)) {
                switch(type) {
                    case 0: // CIDR notation
                        if (load_if_exists(cur_object, "cidr", address)) {
                            auto* c = cidr::cidr_from_str(address.c_str());

                            db_address[name] = std::make_shared<CfgAddress>(std::shared_ptr<AddressObject>(new CidrAddress(c)));
                            db_address[name]->element_name() = name;
                            _dia("cfgapi_load_addresses: cidr '%s': ok", name.c_str());
                        }
                    break;
                    case 1: // FQDN notation
                        if (load_if_exists(cur_object, "fqdn", address))  {

                            db_address[name] = std::make_shared<CfgAddress>(std::shared_ptr<AddressObject>(new FqdnAddress(address)));
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
        }
    }
    
    return num;
}

int CfgFactory::load_db_port () {
    
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
            }
        }
    }
    
    return num;
}

int CfgFactory::load_db_proto () {
    
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
            }
        }
    }
    
    return num;
}


int CfgFactory::load_db_policy () {
    
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_policy: start");
    
    if(cfgapi.getRoot().exists("policy")) {

        num = cfgapi.getRoot()["policy"].getLength();
        _dia("cfgapi_load_policy: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["policy"];

        for( int i = 0; i < num; i++) {
            Setting& cur_object = curr_set[i];

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
            
            bool error = false;

            _dia("cfgapi_load_policy: processing #%d", i);
            
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
                    _dia("cfgapi_load_policy[#%d]: proto object: %s", i, proto.c_str());
                } else {
                    _dia("cfgapi_load_policy[#%d]: proto object not found: %s", i, proto.c_str());
                    error = true;
                    rule->is_disabled = true;
                }
            }
            
            const Setting& sett_src = cur_object["src"];
            if(sett_src.isScalar()) {
                _dia("cfgapi_load_policy[#%d]: scalar src address object", i);
                if(load_if_exists(cur_object, "src", src)) {
                    
                    auto r = lookup_address(src.c_str());
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: src address object: %s", i, src.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src address object not found: %s", i, src.c_str());
                        error = true;
                        rule->is_disabled = true;
                    }
                }
            } else {
                int sett_src_count = sett_src.getLength();
                _dia("cfgapi_load_policy[#%d]: src address list", i);
                for(int y = 0; y < sett_src_count; y++) {
                    const char* obj_name = sett_src[y];
                    
                    auto r = lookup_address(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: src address object: %s", i, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src address object not found: %s", i, obj_name);
                        error = true;
                        rule->is_disabled = true;
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
                        _dia("cfgapi_load_policy[#%d]: src_port object: %s", i, sport.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src_port object not found: %s", i, sport.c_str());
                        error = true;
                        rule->is_disabled = true;
                    }
                }
            } else {
                int sett_sport_count = sett_sport.getLength();
                _dia("cfgapi_load_policy[#%d]: sport list", i);
                for(int y = 0; y < sett_sport_count; y++) {
                    const char* obj_name = sett_sport[y];
                    
                    auto r = lookup_port(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->src_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: src_port object: %s", i, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: src_port object not found: %s", i, obj_name);
                        error = true;
                        rule->is_disabled = true;
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
                        _dia("cfgapi_load_policy[#%d]: dst address object: %s", i, dst.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst address object not found: %s", i, dst.c_str());
                        error = true;
                        rule->is_disabled = true;
                    }                
                }
            } else {
                int sett_dst_count = sett_dst.getLength();
                _dia("cfgapi_load_policy[#%d]: dst list", i);
                for(int y = 0; y < sett_dst_count; y++) {
                    const char* obj_name = sett_dst[y];

                    auto r = lookup_address(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst.push_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst address object: %s", i, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst address object not found: %s", i, obj_name);
                        error = true;
                        rule->is_disabled = true;
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
                        _dia("cfgapi_load_policy[#%d]: dst_port object: %s", i, dport.c_str());
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst_port object not found: %s", i, dport.c_str());
                        error = true;
                        rule->is_disabled = true;
                    }
                }
            } else {
                int sett_dport_count = sett_dport.getLength();
                _dia("cfgapi_load_policy[#%d]: dst_port object list", i);
                for(int y = 0; y < sett_dport_count; y++) {
                    const char* obj_name = sett_dport[y];
                    
                    auto r = lookup_port(obj_name);
                    if(r) {
                        r->usage_add(std::weak_ptr(rule));
                        rule->dst_ports.emplace_back(r);
                        _dia("cfgapi_load_policy[#%d]: dst_port object: %s", i, obj_name);
                    } else {
                        _dia("cfgapi_load_policy[#%d]: dst_port object not found: %s", i, obj_name);
                        error = true;
                        rule->is_disabled = true;
                    }                    
                }
            }
            
            if(load_if_exists(cur_object, "action", action)) {
                int r_a = PolicyRule::POLICY_ACTION_PASS;
                if(action == "deny") {
                    _dia("cfgapi_load_policy[#%d]: action: deny", i);
                    r_a = PolicyRule::POLICY_ACTION_DENY;
                    rule->action_name = action;

                } else if (action == "accept"){
                    _dia("cfgapi_load_policy[#%d]: action: accept", i);
                    r_a = PolicyRule::POLICY_ACTION_PASS;
                    rule->action_name = action;
                } else {
                    _dia("cfgapi_load_policy[#%d]: action: unknown action '%s'", i, action.c_str());
                    r_a  = PolicyRule::POLICY_ACTION_DENY;
                    error = true;
                }
                
                rule->action = r_a;
            } else {
                rule->action = PolicyRule::POLICY_ACTION_DENY;
                rule->action_name = "deny";
            }

            if(load_if_exists(cur_object, "nat", nat)) {
                int nat_a = PolicyRule::POLICY_NAT_NONE;
                
                if(nat == "none") {
                    _dia("cfgapi_load_policy[#%d]: nat: none", i);
                    nat_a = PolicyRule::POLICY_NAT_NONE;
                    rule->nat_name = nat;

                } else if (nat == "auto"){
                    _dia("cfgapi_load_policy[#%d]: nat: auto", i);
                    nat_a = PolicyRule::POLICY_NAT_AUTO;
                    rule->nat_name = nat;
                } else {
                    _dia("cfgapi_load_policy[#%d]: nat: unknown nat method '%s'", i, nat.c_str());
                    nat_a  = PolicyRule::POLICY_NAT_NONE;
                    rule->nat_name = "none";
                    error = true;
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
                        _dia("cfgapi_load_policy[#%d]: detect profile %s", i, name_detection.c_str());
                        rule->profile_detection = std::shared_ptr<ProfileDetection>(prf);
                    }
                    else if(not name_detection.empty()) {
                        _err("cfgapi_load_policy[#%d]: detect profile %s cannot be loaded", i, name_detection.c_str());
                        error = true;
                    }
                }
                
                if(load_if_exists(cur_object, "content_profile", name_content)) {
                    auto prf  = lookup_prof_content(name_content.c_str());
                    if(prf) {
                        prf->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: content profile %s", i, name_content.c_str());
                        rule->profile_content = prf;
                    }
                    else if(not name_content.empty()) {
                        _err("cfgapi_load_policy[#%d]: content profile %s cannot be loaded", i, name_content.c_str());
                        error = true;
                    }
                }                
                if(load_if_exists(cur_object, "tls_profile", name_tls)) {
                    auto tls  = lookup_prof_tls(name_tls.c_str());
                    if(tls) {
                        tls->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: tls profile %s", i, name_tls.c_str());
                        rule->profile_tls= std::shared_ptr<ProfileTls>(tls);
                    }
                    else if(not name_tls.empty()){
                        _err("cfgapi_load_policy[#%d]: tls profile %s cannot be loaded", i, name_tls.c_str());
                        error = true;
                    }
                }         
                if(load_if_exists(cur_object, "auth_profile", name_auth)) {
                    auto auth  = lookup_prof_auth(name_auth.c_str());
                    if(auth) {
                        auth->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: auth profile %s", i, name_auth.c_str());
                        rule->profile_auth= auth;
                    }
                    else if(not name_auth.empty()) {
                        _err("cfgapi_load_policy[#%d]: auth profile %s cannot be loaded", i, name_auth.c_str());
                        error = true;
                    }
                }
                if(load_if_exists(cur_object, "alg_dns_profile", name_alg_dns)) {
                    auto dns  = lookup_prof_alg_dns(name_alg_dns.c_str());
                    if(dns) {
                        dns->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: DNS alg profile %s", i, name_alg_dns.c_str());
                        rule->profile_alg_dns = dns;
                    }
                    else if(not name_alg_dns.empty()) {
                        _err("cfgapi_load_policy[#%d]: DNS alg %s cannot be loaded", i, name_alg_dns.c_str());
                        error = true;
                    }
                }

                if(load_if_exists(cur_object, "script_profile", name_script)) {
                    auto scr  = lookup_prof_script(name_script.c_str());
                    if(scr) {
                        scr->usage_add(std::weak_ptr(rule));
                        _dia("cfgapi_load_policy[#%d]: script profile %s", i, name_script.c_str());
                        rule->profile_script = scr;
                    }
                    else if(not name_script.empty()){
                        _err("cfgapi_load_policy[#%d]: script profile %s cannot be loaded", i, name_script.c_str());
                        error = true;
                    }
                }

                if(load_if_exists(cur_object, "routing", name_routing)) {

                    if(name_routing.empty()) name_routing = "none";

                    if(name_routing != "none") {
                        auto scr = lookup_prof_routing(name_routing.c_str());
                        if (scr) {
                            scr->usage_add(std::weak_ptr(rule));
                            _dia("cfgapi_load_policy[#%d]: routing profile %s", i, name_routing.c_str());
                            rule->profile_routing = scr;
                        } else if (not name_routing.empty()) {
                            _err("cfgapi_load_policy[#%d]: routing profile %s cannot be loaded", i,
                                 name_routing.c_str());
                            error = true;
                        }
                    }
                }


            }
            
            if(!error){
                _dia("cfgapi_load_policy[#%d]: ok", i);

                db_policy_list.push_back(rule);
                db_policy[string_format("[%d]", i)] = rule;
            } else {
                _err("cfgapi_load_policy[#%d]: not ok (will not process traffic)", i);
            }
        }
    }
    
    return num;
}

int CfgFactory::policy_match (baseProxy *proxy) {

    auto const& log = log::policy();

    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int x = 0;
    for( auto const& rule: db_policy_list) {

        bool r = rule->match(proxy);
        
        if(r) {
            _deb("policy_match: matched #%d", x);

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

    _not("policy_match: implicit deny");
    return -1;
}

int CfgFactory::policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    if(index < 0) {
        return -1;
    }
    
    if(index < (signed int)db_policy_list.size()) {
        return db_policy_list.at(index)->action;
    } else {
        _dia("cfg_obj_policy_action[#%d]: out of bounds, deny", index);
        return POLICY_ACTION_DENY;
    }
}

std::shared_ptr<ProfileContent> CfgFactory::policy_prof_content (int index) {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);

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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("cfgapi_load_obj_profile_detect: start");
    
    if(cfgapi.getRoot().exists("detection_profiles")) {

        num = cfgapi.getRoot()["detection_profiles"].getLength();
        _dia("cfgapi_load_obj_profile_detect: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["detection_profiles"];
        
        for( int i = 0; i < num; i++) {
            std::string name;
            auto* a = new ProfileDetection;
            
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
            
            if( load_if_exists(cur_object, "mode", a->mode) ) {

                a->element_name() = name;
                db_prof_detection[name] = std::shared_ptr<ProfileDetection>(a);

                _dia("cfgapi_load_obj_profile_detect: '%s': ok", name.c_str());
            } else {
                _dia("cfgapi_load_obj_profile_detect: '%s': not ok", name.c_str());
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
    std::lock_guard<std::recursive_mutex> l(lock_);


    _dia("load_db_prof_content: start");
    if(not cfgapi.getRoot().exists("content_profiles")) return 0;


    int num = cfgapi.getRoot()["content_profiles"].getLength();
    _dia("load_db_prof_content: found %d objects", num);

    Setting& curr_set = cfgapi.getRoot()["content_profiles"];

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
        }
    }

    return num;
}

int CfgFactory::load_db_tls_ca() {
    return 0;
}

int CfgFactory::load_db_prof_tls () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
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
    std::lock_guard<std::recursive_mutex> l(lock_);

    int num = 0;
    _dia("cfgapi_load_obj_alg_dns_profile: start");
    if(cfgapi.getRoot().exists("alg_dns_profiles")) {
        num = cfgapi.getRoot()["alg_dns_profiles"].getLength();
        _dia("cfgapi_load_obj_alg_dns_profile: found %d objects", num);
        
        Setting& curr_set = cfgapi.getRoot()["alg_dns_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            auto* a = new ProfileAlgDns;
            
            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("cfgapi_load_obj_alg_dns_profile: unnamed object index %d: not ok", i);

                delete a; // coverity: 1407948
                continue;
            }
            
            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _dia("cfgapi_load_obj_alg_dns_profile: processing '%s'", name.c_str());

            a->element_name() = name;
            load_if_exists(cur_object, "match_request_id", a->match_request_id);
            load_if_exists(cur_object, "randomize_id", a->randomize_id);
            load_if_exists(cur_object, "cached_responses", a->cached_responses);
            
            db_prof_alg_dns[name] = std::shared_ptr<ProfileAlgDns>(a);
        }
    }
    
    return num;
}

[[maybe_unused]]
int CfgFactory::load_db_prof_script () {
    std::lock_guard<std::recursive_mutex> l(lock_);

    int num = 0;
    _dia("load_db_prof_script: start");
    if(cfgapi.getRoot().exists("script_profiles")) {
        num = cfgapi.getRoot()["script_profiles"].getLength();
        _dia("load_db_prof_script: found %d objects", num);

        Setting& curr_set = cfgapi.getRoot()["script_profiles"];

        for( int i = 0; i < num; i++) {
            std::string name;
            auto* a = new ProfileScript;

            Setting& cur_object = curr_set[i];

            if (  ! cur_object.getName() ) {
                _dia("load_db_prof_script: unnamed object index %d: not ok", i);

                delete a;
                continue;
            }

            name = cur_object.getName();
            if(name.find("__") == 0) {
                // don't process reserved names
                continue;
            }


            _dia("load_db_prof_script: processing '%s'", name.c_str());

            a->element_name() = name;
            load_if_exists(cur_object, "type", a->script_type);
            load_if_exists(cur_object, "script-file", a->module_path);

            db_prof_script[name] = std::shared_ptr<ProfileScript>(a);
        }
    }

    return num;
}


int CfgFactory::load_db_prof_auth () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int num = 0;

    _dia("load_db_prof_auth: start");

    _dia("load_db_prof_auth: portal settings");
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "address", AuthFactory::get().portal_address);

    load_if_exists<std::string>(cfgapi.getRoot()["settings"]["auth_portal"], "address6", AuthFactory::get().portal_address6);
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "http_port", AuthFactory::get().portal_port_http);
    load_if_exists(cfgapi.getRoot()["settings"]["auth_portal"], "https_port", AuthFactory::get().portal_port_https);

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




int CfgFactory::cleanup_db_address () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_address.size();
    db_address.clear();
    
    _deb("cleanup_db_address: %d objects freed", r);
    return r;
}

int CfgFactory::cleanup_db_policy () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_policy_list.size();
    db_policy_list.clear();
    db_policy.clear();
    
    _deb("cleanup_db_policy: %d objects freed", r);
    return r;
}

int CfgFactory::cleanup_db_port () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_port.size();
    db_port.clear();
    
    return r;
}

int CfgFactory::cleanup_db_proto () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_proto.size();
    db_proto.clear();
    
    return r;
}


int CfgFactory::cleanup_db_prof_content () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_prof_content.size();
    db_prof_content.clear();
    
    return r;
}
int CfgFactory::cleanup_db_prof_detection () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_prof_detection.size();
    db_prof_detection.clear();
    
    return r;
}

int CfgFactory::cleanup_db_tls_ca () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    return 0;
}

int CfgFactory::cleanup_db_prof_tls () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_prof_tls.size();
    db_prof_tls.clear();
    
    return r;
}

int CfgFactory::cleanup_db_prof_alg_dns () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_prof_alg_dns.size();
    db_prof_alg_dns.clear();
    
    return r;
}

int CfgFactory::cleanup_db_prof_script () {
    std::lock_guard<std::recursive_mutex> l(lock_);

    int r = db_prof_script.size();
    if(r > 0)
        db_prof_script.clear();

    return r;
}


int CfgFactory::cleanup_db_prof_auth () {
    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int r = db_prof_auth.size();
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
            mitm_proxy->writer_opts()->format = pc->write_format;

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
            std::string msg("Connection start\n");

            mitm_proxy->toggle_tlog();
            mitm_proxy->tlog()->write_left(msg);
        }
    } else {
        _war("policy_apply: cannot apply content profile: cast to MitmProxy failed.");
        ret = false;
    } 
    
    return ret;
}


bool CfgFactory::prof_detect_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileDetection> &pd) {

    auto* mitm_originator = dynamic_cast<AppHostCX*>(originator);
    auto const& log = log::policy();

    const char* pd_name = "none";
    bool ret = true;
    
    // we scan connection on client's side
    if(mitm_originator != nullptr) {
        mitm_originator->mode(AppHostCX::MODE_NONE);
        if(pd != nullptr)  {
            pd_name = pd->element_name().c_str();
            _dia("policy_apply[%s]: policy detection profile: mode: %d", pd_name, pd->mode);
            mitm_originator->mode(static_cast<AppHostCX::mode_t>(pd->mode));
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
        std::scoped_lock<std::recursive_mutex> dd_(DNS::get_domain_lock());

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
                #ifdef USE_PYHON
                auto* n = new PythonInspector();
                if(n->l4_prefilter(mh)) {
                    mh->inspectors_.push_back(n);
                    ret = true;
                }
                else {
                    delete n;
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


int CfgFactory::policy_apply (baseHostCX *originator, baseProxy *proxy, int matched_policy) {

    auto const& log = log::policy();

    std::lock_guard<std::recursive_mutex> l(lock_);
    
    int policy_num = matched_policy;
    if(policy_num < 1) {
        policy_num = policy_match(proxy);
    }

    int verdict = policy_action(policy_num);
    if(verdict == POLICY_ACTION_PASS) {

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
        if (pd) {
            if(prof_detect_apply(originator, proxy, pd)) {
                pd_name = pd->element_name().c_str();
            }
        }
        
        /* Processing TLS profile*/
        if (pt) {
            if(prof_tls_apply(originator, proxy, pt)) {
                pt_name = pt->element_name().c_str();
            }
        }
        
        /* Processing ALG : DNS*/
        if (p_alg_dns) {
            if (prof_alg_dns_apply(originator, proxy, p_alg_dns)) {
                algs_name += p_alg_dns->element_name();
            }
        }

        
        auto* mitm_proxy = dynamic_cast<MitmProxy*>(proxy);
        
        /* Processing Auth profile */
        if(pa && mitm_proxy) {
            // auth is applied on proxy
            mitm_proxy->opt_auth_authenticate = pa->authenticate;
            mitm_proxy->opt_auth_resolve = pa->resolve;
            
            pa_name = pa->element_name().c_str();
        } 
        
        // ALGS can operate only on MitmHostCX classes

        
        _inf("Connection %s accepted: policy=%d cont=%s det=%s tls=%s auth=%s algs=%s", originator->full_name('L').c_str(), policy_num, pc_name, pd_name, pt_name, pa_name, algs_name.c_str());
        
    } else {
        _inf("Connection %s denied: policy=%d", originator->full_name('L').c_str(), policy_num);
    }
    
    return policy_num;
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
        sslcom->opt_bypass = !pt->inspect;
        if(sslcom->opt_bypass) {
            sslcom->verify_reset(SSLCom::VRF_OK);
        }

        sslcom->opt_allow_unknown_issuer = pt->allow_untrusted_issuers;
        sslcom->opt_allow_self_signed_chain = pt->allow_untrusted_issuers;
        sslcom->opt_allow_not_valid_cert = pt->allow_invalid_certs;
        sslcom->opt_allow_self_signed_cert = pt->allow_self_signed;

        sslcom->opt_failed_certcheck_replacement = pt->failed_certcheck_replacement;
        sslcom->opt_failed_certcheck_override = pt->failed_certcheck_override;
        sslcom->opt_failed_certcheck_override_timeout = pt->failed_certcheck_override_timeout;
        sslcom->opt_failed_certcheck_override_timeout_type = pt->failed_certcheck_override_timeout_type;

        auto* peer_sslcom = dynamic_cast<SSLCom*>(sslcom->peer());

        if( peer_sslcom &&
                pt->failed_certcheck_replacement &&
                should_redirect(pt, peer_sslcom)) {

            _deb("policy_apply_tls: applying profile, repl=%d, repl_ovrd=%d, repl_ovrd_tmo=%d, repl_ovrd_tmo_type=%d",
                 pt->failed_certcheck_replacement,
                 pt->failed_certcheck_override,
                 pt->failed_certcheck_override_timeout,
                 pt->failed_certcheck_override_timeout_type );

            peer_sslcom->opt_failed_certcheck_replacement = pt->failed_certcheck_replacement;
            peer_sslcom->opt_failed_certcheck_override = pt->failed_certcheck_override;
            peer_sslcom->opt_failed_certcheck_override_timeout = pt->failed_certcheck_override_timeout;
            peer_sslcom->opt_failed_certcheck_override_timeout_type = pt->failed_certcheck_override_timeout_type;
        }

        // set accordingly if general "use_pfs" is specified, more concrete settings come later
        sslcom->opt_left_kex_dh = pt->use_pfs;
        sslcom->opt_right_kex_dh = pt->use_pfs;

        sslcom->opt_left_kex_dh = pt->left_use_pfs;
        sslcom->opt_right_kex_dh = pt->right_use_pfs;

        sslcom->opt_left_no_tickets = pt->left_disable_reuse;
        sslcom->opt_right_no_tickets = pt->right_disable_reuse;

        sslcom->opt_ocsp_mode = pt->ocsp_mode;
        sslcom->opt_ocsp_stapling_enabled = pt->ocsp_stapling;
        sslcom->opt_ocsp_stapling_mode = pt->ocsp_stapling_mode;

        // certificate transparency
        sslcom->opt_ct_enable = pt->opt_ct_enable;

        // alpn alpn
        sslcom->opt_alpn_block = pt->opt_alpn_block;

        if(pt->sni_filter_bypass) {
            if( ! pt->sni_filter_bypass->empty() ) {
                sslcom->sni_filter_to_bypass() = pt->sni_filter_bypass;
            }
        }

        sslcom->sslkeylog = pt->sslkeylog;

        tls_applied = true;
    } else {
        _err("CfgFactory::policy_apply_tls[%s]: is not SSL", xcom->shortname().c_str());
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

int CfgFactoryBase::apply_tenant_index(std::string& what, int& idx) const {
    _deb("apply_index: what=%s idx=%d", what.c_str(), idx);
    int port = std::stoi(what);
    what = std::to_string(port + idx);

    return 0;
}


bool CfgFactory::apply_tenant_config () {
    int ret = 0;

    if( (  tenant_index >= 0 ) && ( ! tenant_name.empty() ) ) {
        ret += apply_tenant_index(listen_tcp_port, tenant_index);
        ret += apply_tenant_index(listen_tls_port, tenant_index);
        ret += apply_tenant_index(listen_dtls_port, tenant_index);
        ret += apply_tenant_index(listen_udp_port, tenant_index);
        ret += apply_tenant_index(listen_socks_port, tenant_index);
        ret += apply_tenant_index(AuthFactory::get().portal_port_http, tenant_index);
        ret += apply_tenant_index(AuthFactory::get().portal_port_https, tenant_index);

        CliState::get().cli_port += tenant_index;
    }

    return (ret == 0);
}


bool CfgFactory::new_address_object(Setting& ex, std::string const& name) const {

    try {
        Setting &item = ex.add(name, Setting::TypeGroup);
        item.add("type", Setting::TypeInt) = 0;  // cidr
        item.add("cidr", Setting::TypeString) = "0.0.0.0/32";
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
            Setting &s_type = item.add("type", Setting::TypeInt);
            Setting &s_fqdn = item.add("fqdn", Setting::TypeString);

            s_type = 1;
            auto fqdn_ptr = std::dynamic_pointer_cast<FqdnAddress>(obj->value());
            if(fqdn_ptr) {
                s_fqdn = fqdn_ptr->fqdn();
            }

            n_saved++;
        }
        else
        if(obj->value()->c_type() == std::string("CidrAddress")) {
            Setting &s_type = item.add("type", Setting::TypeInt);
            Setting &s_cidr = item.add("cidr", Setting::TypeString);

            s_type = 0;

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


int CfgFactory::cleanup_db_routing () {
    std::lock_guard<std::recursive_mutex> l(lock_);

    int r = db_routing.size();
    db_routing.clear();

    return r;
}

int CfgFactory::load_db_routing () {

    std::lock_guard<std::recursive_mutex> l(lock_);

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
    deb_log_objects.add("sslcom", Setting::TypeInt) = (int)SSLCom::log_level_ref().level_ref();
    deb_log_objects.add("sslmitmcom", Setting::TypeInt) = (int)baseSSLMitmCom<DTLSCom>::log_level_ref().level_ref();
    deb_log_objects.add("sslcertstore", Setting::TypeInt) = (int)SSLFactory::get_log().level()->level_ref();
    deb_log_objects.add("proxy", Setting::TypeInt) = (int)baseProxy::log_level_ref().level_ref();
    deb_log_objects.add("epoll", Setting::TypeInt) = (int)epoll::log_level.level_ref();

    deb_log_objects.add("mtrace", Setting::TypeBoolean) = cfg_mtrace_enable;
    deb_log_objects.add("openssl_mem_dbg", Setting::TypeBoolean) = cfg_openssl_mem_dbg;

    deb_log_objects.add("alg_dns", Setting::TypeInt) = (int)DNS_Inspector::log_level_ref().level_ref();
    deb_log_objects.add("pkt_dns", Setting::TypeInt) = (int)DNS_Packet::log_level_ref().level_ref();


    return 0;
}


bool CfgFactory::new_detection_profile(Setting& ex, std::string const& name) const {

    try {
        Setting& item = ex.add(name, Setting::TypeGroup);
        item.add("mode", Setting::TypeInt) = 1; // MODE_PRE
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

        newpol.add("proto", Setting::TypeString) = "tcp";

        newpol.add("src", Setting::TypeArray);
        newpol.add("sport", Setting::TypeArray);
        newpol.add("dst", Setting::TypeArray);
        newpol.add("dport", Setting::TypeArray);
        newpol.add("action", Setting::TypeString) = "accept";
        newpol.add("nat", Setting::TypeString) = "auto";

        newpol.add("tls_profile", Setting::TypeString);
        newpol.add("detection_profile", Setting::TypeString);
        newpol.add("content_profile", Setting::TypeString);
        newpol.add("auth_profile", Setting::TypeString);
        newpol.add("alg_dns_profile", Setting::TypeString);
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

                for (auto f: sig->sig_chain()) {


                    bool sig_correct = false;

                    char sig_side = f.first;
                    baseMatch *bm = f.second;


                    unsigned int sig_bytes_start = bm->match_limits_offset;
                    unsigned int sig_bytes_max = bm->match_limits_bytes;
                    std::string sig_type;
                    std::string sig_expr;


                    // follow the inheritance (regex can also be cast to simple)
                    auto rm = dynamic_cast<regexMatch *>(bm);
                    if (rm) {
                        sig_type = "regex";
                        sig_expr = rm->expr();
                        sig_correct = true;
                    } else {
                        auto sm = dynamic_cast<simpleMatch *>(bm);
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
        it_ns.add(Setting::TypeString) = ns;
    }

    objects.add("certs_path", Setting::TypeString) = SSLFactory::certs_path();
    objects.add("certs_ca_key_password", Setting::TypeString) = SSLFactory::certs_password();
    objects.add("certs_ctlog", Setting::TypeString) = SSLFactory::ctlogfile();
    objects.add("ca_bundle_path", Setting::TypeString) = SSLFactory::ca_path();

    objects.add("plaintext_port", Setting::TypeString) = CfgFactory::get()->listen_tcp_port_base;
    objects.add("plaintext_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_tcp;

    objects.add("ssl_port", Setting::TypeString) = CfgFactory::get()->listen_tls_port_base;
    objects.add("ssl_workers", Setting::TypeInt) = CfgFactory::get()->num_workers_tls;
    objects.add("ssl_autodetect", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect;
    objects.add("ssl_autodetect_harder", Setting::TypeBoolean) = MitmMasterProxy::ssl_autodetect_harder;
    objects.add("ssl_ocsp_status_ttl", Setting::TypeInt) = SSLFactory::ssl_ocsp_status_ttl;
    objects.add("ssl_crl_status_ttl", Setting::TypeInt) = SSLFactory::ssl_crl_status_ttl;

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

    Setting& cli_objects = objects.add("cli", Setting::TypeGroup);
    cli_objects.add("port", Setting::TypeInt) = CliState::get().cli_port_base;
    cli_objects.add("enable_password", Setting::TypeString) = CliState::get().cli_enable_password;


    Setting& auth_objects = objects.add("auth_portal", Setting::TypeGroup);
    auth_objects.add("address", Setting::TypeString) = CfgFactory::get()->auth_address;
    auth_objects.add("http_port", Setting::TypeString) = CfgFactory::get()->auth_http;
    auth_objects.add("https_port", Setting::TypeString) = CfgFactory::get()->auth_https;
    auth_objects.add("ssl_key", Setting::TypeString) = CfgFactory::get()->auth_sslkey;
    auth_objects.add("ssl_cert", Setting::TypeString) = CfgFactory::get()->auth_sslcert;
    auth_objects.add("magic_ip", Setting::TypeString) = CfgFactory::get()->tenant_magic_ip;


    objects.add("write_payload_dir", Setting::TypeString) = CfgFactory::get()->traflog_dir;
    objects.add("write_payload_file_prefix", Setting::TypeString) = CfgFactory::get()->traflog_file_prefix;
    objects.add("write_payload_file_suffix", Setting::TypeString) = CfgFactory::get()->traflog_file_suffix;
    objects.add("write_pcap_single_quota", Setting::TypeInt) = static_cast<int>(traflog::PcapLog::single_instance().stat_bytes_quota/(1024*1024));


    return 0;
}


int CfgFactory::save_config() const {

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
    }
    catch(ConfigException const& e) {
        _err("error writing config file %s", e.what());
        return -1;
    }

    return n;
}
