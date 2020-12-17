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

#ifndef CFGAPI_HPP
 #define CFGAPI_HPP

#include <vector>
#include <map>
#include <mutex>
#include <chrono>
 
#include <libconfig.h++>
#include <ext/libcidr/cidr.hpp>
#include <ranges.hpp>
#include <policy/policy.hpp>
#include <sslcom.hpp>

#include <shm/shmauth.hpp>


using namespace libconfig;

class CfgFactoryBase {
public:
    CfgFactoryBase(): log(get_log()) {}
    CfgFactoryBase(CfgFactoryBase const &) = delete;
    void operator=(const CfgFactoryBase&) = delete;

    logan_lite& log;
    static logan_lite& get_log() {
        static logan_lite l("config");
        return l;
    }

    std::string config_file;
    int tenant_index = -1;
    std::string tenant_name;

    loglevel internal_init_level = INF;
    loglevel cli_init_level = NON;

    virtual bool apply_tenant_config() = 0;
    int  apply_tenant_index(std::string& what, int& idx) const;
};


class CfgFactory : public CfgFactoryBase {

    CfgFactory();

    Config cfgapi;
    std::recursive_mutex lock_;

public:
    CfgFactory(CfgFactory const &) = delete;
    void operator=(const CfgFactory&) = delete;
    virtual ~CfgFactory() { cleanup(); }

    static CfgFactory& get() {
        static CfgFactory fac;
        return fac;
    }


    static std::recursive_mutex& lock() { return get().lock_; }
    static Setting& cfg_root() { return get().cfgapi.getRoot(); }
    static Config&  cfg_obj() { return get().cfgapi; }

    loglevel args_debug_flag;

    std::string listen_tcp_port_base;
    std::string listen_tls_port_base;
    std::string listen_dtls_port_base;
    std::string listen_udp_port_base;
    std::string listen_socks_port_base;

    std::string listen_tcp_port;
    std::string listen_tls_port;
    std::string listen_dtls_port;
    std::string listen_udp_port;
    std::string listen_socks_port;

    std::string dir_msg_templates;

    bool config_file_check_only;

    bool accept_tproxy = true;
    bool accept_redirect = true;
    bool accept_socks = true;

    int num_workers_tcp;
    int num_workers_tls;
    int num_workers_dtls;
    int num_workers_udp;
    int num_workers_socks;


    std::string syslog_server;
    int syslog_port;
    int syslog_facility;
    loglevel syslog_level;
    int syslog_family;


    std::string log_file_base;
    std::string sslkeylog_file_base;

    std::string log_file;
    std::string sslkeylog_file;
    bool log_console{};


    // macro to define maps attribute, plus accessor functions
    #define DB_MAP(type, name) \
    std::map<std::string, type> name; \
    std::vector<std::string> keys_of_##name() const  {\
        std::vector<std::string> rr; \
        for(auto const& it:  name )  rr.push_back(it.first); \
        return rr; \
    }

    DB_MAP(std::shared_ptr<CfgElement>, db_address);
    DB_MAP(std::shared_ptr<CfgElement>, db_port);
    DB_MAP(std::shared_ptr<CfgElement> , db_proto);
    std::vector<std::shared_ptr<PolicyRule>> db_policy;
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_detection);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_content);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_tls);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_tls_ca);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_auth);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_alg_dns);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_script);

    mp::vector<int> db_udp_quick_ports;


    std::string auth_address;
    std::string auth_http;
    std::string auth_https;
    std::string auth_sslkey;
    std::string auth_sslcert;
    std::string tenant_magic_ip;


    std::string traflog_dir;
    std::string traflog_file_prefix;
    std::string traflog_file_suffix;


    std::vector<std::string> db_nameservers;


public:
    bool  cfgapi_init(const char* fnm);
    void  cleanup();

    template <class T>
    std::shared_ptr<T> section_element(std::string const& section, std::string const& key);
    std::map<std::string, std::shared_ptr<CfgElement>>& section_db(std::string const& section);

    std::shared_ptr<CfgAddress> lookup_address (const char *name);
    std::shared_ptr<CfgRange> lookup_port (const char *name);
    std::shared_ptr<CfgUint8> lookup_proto (const char *name);
    std::shared_ptr<ProfileDetection> lookup_prof_detection (const char *name);
    std::shared_ptr<ProfileContent> lookup_prof_content (const char *name);
    std::shared_ptr<ProfileTls> lookup_prof_tls (const char *name);
    std::shared_ptr<ProfileAuth> lookup_prof_auth (const char *name);
    std::shared_ptr<ProfileAlgDns> lookup_prof_alg_dns (const char *name);
    std::shared_ptr<ProfileScript> lookup_prof_script (const char *name);

    bool apply_tenant_config() override;

    bool load_settings ();
    int  load_debug();
    int  load_db_address ();
    int  load_db_port ();
    int  load_db_proto ();
    int  load_db_policy ();
    int  load_db_prof_content ();
    int  load_db_prof_detection ();
    int  load_db_tls_ca();
    int  load_db_prof_tls ();
    int  load_db_prof_auth ();
    int  load_db_prof_alg_dns ();

    [[maybe_unused]]
    int  load_db_prof_script ();


    bool new_address_object(Setting& ex, std::string const& name) const;
    int save_address_objects(Config& ex) const;

    bool new_port_object(Setting& ex, std::string const& name) const;
    int save_port_objects(Config& ex) const;

    bool new_proto_object(Setting& section, std::string const& name) const;
    int save_proto_objects(Config& ex) const;

    int save_debug(Config& ex) const;

    bool new_detection_profile(Setting& ex, std::string const& name) const;
    int save_detection_profiles(Config& ex) const;

    bool new_content_profile(Setting& ex, std::string const& name) const;
    int save_content_profiles(Config& ex) const;

    bool new_tls_ca(Setting& ex, std::string const& name) const;
    int save_tls_ca(Config& ex) const;

    bool new_tls_profile(Setting& ex, std::string const& name) const;
    int save_tls_profiles(Config& ex) const;

    bool new_alg_dns_profile(Setting& ex, std::string const& name) const;
    int save_alg_dns_profiles(Config& ex) const;

    bool new_auth_profile(Setting& ex, std::string const& name) const;
    int save_auth_profiles(Config& ex) const;

    bool new_policy(Setting& ex, std::string const& name) const;
    int save_policy(Config& ex) const;

    [[nodiscard]] int save_config() const;


    int  cleanup_db_address ();
    int  cleanup_db_port ();
    int  cleanup_db_proto ();
    int  cleanup_db_policy ();
    int  cleanup_db_prof_content ();
    int  cleanup_db_prof_detection ();
    int  cleanup_db_tls_ca ();
    int  cleanup_db_prof_tls ();
    int  cleanup_db_prof_auth ();
    int  cleanup_db_prof_alg_dns ();
    int  cleanup_db_prof_script ();

    int policy_match (baseProxy *proxy);
    int policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right);
    int policy_action (int index);
    int policy_apply (baseHostCX *originator, baseProxy *proxy, int matched_policy=-1);

    bool policy_apply_tls (int policy_num, baseCom *xcom);
    bool policy_apply_tls (const std::shared_ptr<ProfileTls> &pt, baseCom *xcom);

    bool prof_content_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileContent> &pc);
    bool prof_detect_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileDetection> &pd);
    bool prof_tls_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileTls> &ps);
    bool prof_alg_dns_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileAlgDns>& p_alg_dns);
    [[maybe_unused]]
    bool prof_script_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileScript>& p_script);

    bool should_redirect (const std::shared_ptr<ProfileTls> &pt, SSLCom *com);

    void log_version (bool warn_delay = true);

    std::shared_ptr<ProfileContent> policy_prof_content (int index);
    std::shared_ptr<ProfileDetection> policy_prof_detection (int index);
    std::shared_ptr<ProfileTls> policy_prof_tls (int index);
    std::shared_ptr<ProfileAuth> policy_prof_auth (int index);
    std::shared_ptr<ProfileAlgDns> policy_prof_alg_dns (int index);
    [[maybe_unused]]
    std::shared_ptr<ProfileScript> policy_prof_script (int index);

    #ifndef MEM_DEBUG
    bool cfg_openssl_mem_dbg = false;
    bool cfg_mtrace_enable = false;
    #else
    bool cfg_openssl_mem_dbg = true;
        bool cfg_mtrace_enable = true;
    #endif
};


template <class T>
inline std::shared_ptr<T> CfgFactory::section_element(std::string const& section, std::string const& key) {
    return std::dynamic_pointer_cast<T>(section_db(section)[key]);
}

// HELPERS

// load value from config if the config key exists - this is workaround to some versions
// of libconfig++ on armhf which don't keep the promise and lookupValue throws an exception

template <class T>
bool load_if_exists(libconfig::Setting const& s, const char* key, T& valref) {
    if(s.exists(key)) {
        s.lookupValue(key, valref);

        return true;
    }

    return false;
}


#endif