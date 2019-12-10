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
#include <ext/cidr.hpp>
#include <ranges.hpp>
#include <policy.hpp>
#include <sslcom.hpp>

#include <shmauth.hpp>


using namespace libconfig;

class CfgFactory {

    CfgFactory();

    Config cfgapi;
    std::recursive_mutex lock_;
    logan_lite& log;

    static logan_lite& get_log() {
        static logan_lite l("config");
        return l;
    }

public:
    CfgFactory(CfgFactory const &) = delete;
    void operator=(const CfgFactory&) = delete;

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

    std::string config_file;
    int tenant_index = -1;
    std::string tenant_name;
    std::string dir_msg_templates;

    bool config_file_check_only;

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


    std::time_t ts_sys_started{};

    std::map<std::string, AddressObject *> db_address;
    std::map<std::string, range> db_port;
    std::map<std::string, int> db_proto;
    std::vector<PolicyRule *> db_policy;
    std::map<std::string, ProfileDetection *> db_prof_detection;
    std::map<std::string, ProfileContent *> db_prof_content;
    std::map<std::string, ProfileTls *> db_prof_tls;
    std::map<std::string, ProfileAuth *> db_prof_auth;
    std::map<std::string, ProfileAlgDns *> db_prof_alg_dns;
    std::map<std::string, ProfileScript *> db_prof_script;

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
    void  cfgapi_cleanup();

    AddressObject*    lookup_address (const char *name);
    range             lookup_port (const char *name);
    int               lookup_proto (const char *name);
    ProfileDetection* lookup_prof_detection (const char *name);
    ProfileContent*   lookup_prof_content (const char *name);
    ProfileTls*       lookup_prof_tls (const char *name);
    ProfileAuth*      lookup_prof_auth (const char *name);
    ProfileAlgDns*    lookup_prof_alg_dns (const char *name);
    ProfileScript*    lookup_prof_script (const char *name);

    bool apply_tenant_config ();
    int  apply_tenant_index(std::string& what, int& idx);

    bool load_settings ();
    int  load_db_address ();
    int  load_db_port ();
    int  load_db_proto ();
    int  load_db_policy ();
    int  load_db_prof_content ();
    int  load_db_prof_detection ();
    int  load_db_prof_tls ();
    int  load_db_prof_auth ();
    int  load_db_prof_alg_dns ();
    int  load_db_prof_script ();

    int  cleanup_db_address ();
    int  cleanup_db_port ();
    int  cleanup_db_proto ();
    int  cleanup_db_policy ();
    int  cleanup_db_prof_content ();
    int  cleanup_db_prof_detection ();
    int  cleanup_db_prof_tls ();
    int  cleanup_db_prof_auth ();
    int  cleanup_db_prof_alg_dns ();
    int  cleanup_db_prof_script ();

    int policy_match (baseProxy *proxy);
    int policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right);
    int policy_action (int index);
    int policy_apply (baseHostCX *originator, baseProxy *proxy);

    bool policy_apply_tls (int policy_num, baseCom *xcom);
    bool policy_apply_tls (ProfileTls *pt, baseCom *xcom);

    bool prof_content_apply (baseHostCX *originator, baseProxy *new_proxy, ProfileContent *pc);
    bool prof_detect_apply (baseHostCX *originator, baseProxy *new_proxy, ProfileDetection *pd);
    bool prof_tls_apply (baseHostCX *originator, baseProxy *new_proxy, ProfileTls *ps);
    bool prof_alg_dns_apply (baseHostCX *originator, baseProxy *new_proxy, ProfileAlgDns *p_alg_dns);
    bool prof_script_apply (baseHostCX *originator, baseProxy *new_proxy, ProfileScript *p_script);

    bool should_redirect (ProfileTls *pt, SSLCom *com);

    void log_version (bool warn_delay = true);

    ProfileContent* policy_prof_content (int index);
    ProfileDetection* policy_prof_detection (int index);
    ProfileTls* policy_prof_tls (int index);
    ProfileAuth* policy_prof_auth (int index);
    ProfileAlgDns* policy_prof_alg_dns (int index);
    ProfileScript* policy_prof_script (int index);
};

struct logging_{
    loglevel level = INF;
    loglevel cli_init_level = NON;
} ;

struct cfgapi_table_ {
    logging_ logging;
};


extern struct cfgapi_table_ cfgapi_table;




#endif