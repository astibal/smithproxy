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
#include <traflog/pcaplog.hpp>

#include <shm/shmauth.hpp>




class CfgFactoryBase {
public:
    CfgFactoryBase() = default;
    CfgFactoryBase(CfgFactoryBase const &) = delete;
    virtual ~CfgFactoryBase() = default;
    void operator=(const CfgFactoryBase&) = delete;

    struct log { ;
        static logan_lite &config() {
            static logan_lite l("config");
            return l;
        }
        static logan_lite &policy() {
            static logan_lite l("policy");
            return l;
        }
    };

    logan_lite& log = log::config();

    std::string config_file;
    unsigned int tenant_index = 0;
    std::string tenant_name = "default";

    loglevel internal_init_level = INF;
    loglevel cli_init_level = NON;

    virtual bool apply_tenant_config() = 0;
    int  apply_tenant_index(std::string& what, unsigned int const& idx) const;
};

struct UpdateBoard {
    static constexpr inline uint64_t starting_num = 1000L;

    struct UpdateInfo {
        uint64_t seen_current { starting_num };
        uint64_t seen_saved { starting_num };
    };

    // pair of seen current version, seen saved version - maintained by subscriber
    using update_info_t = UpdateInfo;

    // subscriber-id -> update info
    using subscriber_map_t = std::unordered_map<std::string, update_info_t>;

    void subscribe(std::string const& sub_id) { board_[sub_id] = { current_version_, saved_version_ }; };
    void unsubscribe(std::string const& sub_id) { board_.erase(sub_id); };

    update_info_t& at(std::string const& sub_id) {
        return board_[sub_id];
    };
    update_info_t& operator[](std::string const& sub_id) { return at(sub_id); }

    bool differs_current(std::string const& sub_id) {
        return ( at(sub_id).seen_current != current_version_ );
    }
    bool differs_saved(std::string const& sub_id) {
        return ( at(sub_id).seen_saved != saved_version_ );
    }
    bool differs(std::string const& sub_id) {
        return ( differs_current(sub_id) or differs_saved(sub_id) );
    }

    // return current version difference
    // negative - means rollback to older version
    // zero - versions are the same
    // positive - seen version is newer, config is updated
    int64_t current_delta(std::string const& sub_id) {
        return current_version_ - at(sub_id).seen_current;
    }

    // return saved version difference
    // negative - older save has been applied
    // zero - no new saves
    // positive - new config version has been saved
    int64_t saved_delta(std::string const& sub_id) {
        return saved_version_ - at(sub_id).seen_saved;
    }


    void ack_current(std::string const& sub_id) {
        at(sub_id).seen_current = current_version_;
    }
    void ack_saved(std::string const& sub_id) {
        at(sub_id).seen_saved = saved_version_;
    }


    uint64_t upgrade(std::string const& sid) { updater_ = sid; return ++current_version_; }
    uint64_t rollback(std::string const& sid) { updater_ = sid; return current_version_ = saved_version_; }
    uint64_t save(std::string const& sid) { updater_ = sid; saved_version_ = current_version_; return saved_version_; }

    std::string const& updater() const {return updater_; }
    uint64_t version_current() const noexcept { return current_version_; }
    uint64_t version_saved() const noexcept { return saved_version_; }

    uint64_t current_version_ = starting_num;
    uint64_t saved_version_ = starting_num;
    subscriber_map_t board_;
    std::string updater_;
};


//RAII sub mechanics

struct UpdateBoardSubscriber {
    UpdateBoardSubscriber() = delete;
    UpdateBoardSubscriber(std::string const& sub_id, std::shared_ptr<UpdateBoard> board) : my_id(sub_id), board_(board) {};
    ~UpdateBoardSubscriber() {
        auto shr = board_.lock();
        if(shr) {
            shr->unsubscribe(my_id);
        }
    }

    auto board() { return board_.lock(); }

    std::string my_id;
    std::weak_ptr<UpdateBoard> board_;
};


struct SignatureTree;

class CfgFactory : public CfgFactoryBase {

    libconfig::Config cfgapi;
    std::recursive_mutex lock_;

    static inline std::shared_ptr<CfgFactory> self;
    static inline std::shared_ptr<UpdateBoard> update_board;

public:
//    static inline bool config_changed_flag = false;

    // Each version bump implies a config upgrade - we start on 1000
    constexpr static inline const int SCHEMA_VERSION  = 1012;

    CfgFactory() = default;
    CfgFactory(CfgFactory const &) = delete;
    void operator=(const CfgFactory&) = delete;
    ~CfgFactory() override { cleanup(); }

    static void init() {
        self = std::make_shared<CfgFactory>();
        update_board = std::make_shared<UpdateBoard>();
    }

    static std::shared_ptr<CfgFactory> get() {
        return CfgFactory::self;
    }

    static std::shared_ptr<UpdateBoard> board() {
        return CfgFactory::update_board;
    }


    static std::recursive_mutex& lock() { return get()->lock_; }
    static libconfig::Setting& cfg_root() { return get()->cfgapi.getRoot(); }
    static libconfig::Config&  cfg_obj() { return get()->cfgapi; }

    loglevel args_debug_flag = NON;

    std::string internal_version;
    int         schema_version = SCHEMA_VERSION;

    std::string listen_tcp_port_base = "50080";
    std::string listen_tls_port_base = "50443";
    std::string listen_dtls_port_base = "50443";
    std::string listen_udp_port_base = "50080";
    std::string listen_socks_port_base = "1080";

    std::string listen_tcp_port = "50080";
    std::string listen_tls_port = "50443";
    std::string listen_dtls_port = "50443";
    std::string listen_udp_port = "50080";
    std::string listen_socks_port = "1080";

    std::string dir_msg_templates = "/etc/smithproxy/msg/en/";

    bool config_file_check_only = false;

    bool accept_tproxy = true;
    bool accept_redirect = true;
    bool accept_socks = true;
    bool accept_api = true;

    std::string admin_group;

    int num_workers_tcp = 0;
    int num_workers_tls = 0;
    int num_workers_dtls = 0;
    int num_workers_udp  = 0;
    int num_workers_socks = 0;

    int cli_port = 50000;
    int cli_port_base = 50000;
    std::string cli_enable_password;

    std::string syslog_server;
    int syslog_port     = 514;
    int syslog_facility = 23; //local7
    int syslog_family   = 4;
    loglevel syslog_level = INF;


    std::string log_file_base;
    std::string sslkeylog_file_base;

    std::string log_file;
    std::string sslkeylog_file;
    bool log_console = false;


    // macro to define maps attribute, plus accessor functions
    #define DB_MAP(type, name) \
    std::map<std::string, type> name; \
    std::vector<std::string> keys_of_##name() const  {\
        std::vector<std::string> rr; \
        for(auto const& it:  name )  rr.push_back(it.first); \
        return rr; \
    }                          \
    std::vector<std::string> keys_of_##name##_or_none() const  {\
        std::vector<std::string> rr; \
        for(auto const& it:  name )  rr.push_back(it.first); \
        rr.emplace_back("none"); \
        return rr; \
    }

    DB_MAP(std::shared_ptr<CfgElement>, db_address);
    DB_MAP(std::shared_ptr<CfgElement>, db_port);
    DB_MAP(std::shared_ptr<CfgElement> , db_proto);

    DB_MAP(std::shared_ptr<CfgElement> , db_policy);
    std::vector<std::shared_ptr<PolicyRule>> db_policy_list;

    DB_MAP(std::shared_ptr<CfgElement> , db_routing);

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


    struct {
        bool enabled = true;
        std::string dir = "/var/smithproxy/data";
        std::string file_prefix;
        std::string file_suffix;
        ContentCaptureFormat format { ContentCaptureFormat::type_t::PCAP_SINGLE };

    } capture_local;

    struct {
        bool enabled = false;
        std::string tun_type = "gre";
        std::string tun_dst = "127.0.0.1";
        int tun_ttl {1};
    } capture_remote;


    std::vector<std::string> db_nameservers;

    bool  cfgapi_init(const char* fnm);
    void  cleanup();

    static void cfg_clone_setting(libconfig::Setting& dst, libconfig::Setting& orig, int index = -1 );
    static int cfg_write(libconfig::Config& cfg, FILE* where, unsigned long iobufsz = 0);

    static std::pair<bool, std::string> cfg_add_prepare_params(std::string const& section, std::vector<std::string>& args);
    std::pair<bool, std::string> cfg_add_entry(std::string const& section_name, std::string const& entry_name);
    static bool _apply_new_entry(std::string const& section, std::string const& entry_name);

    bool write_value(libconfig::Setting& setting, std::optional<std::string> string_value, libconfig::Setting::Type add_as_type = libconfig::Setting::TypeNone);
    std::pair<bool, std::string> cfg_write_value(libconfig::Setting& parent, bool create, std::string& varname, const std::vector<std::string> &values);

    //sections containing unnamed lists (ie. traffic policy)
    static inline std::set<std::string, std::less<>> section_lists = { "policy", };
    size_t section_list_size(std::string const& section) const;

    template <class T>
    std::shared_ptr<T> section_element(std::string const& section, std::string const& key);
    std::map<std::string, std::shared_ptr<CfgElement>>& section_db(std::string const& section);

    std::shared_ptr<CfgAddress> lookup_address (const char *name);
    std::vector<std::shared_ptr<CidrAddress>>
    expand_to_cidr (std::vector<std::string> const &address_names, int cidr_flags);

    std::shared_ptr<CfgRange> lookup_port (const char *name);
    std::shared_ptr<CfgUint8> lookup_proto (const char *name);
    std::shared_ptr<ProfileDetection> lookup_prof_detection (const char *name);
    std::shared_ptr<ProfileContent> lookup_prof_content (const char *name);
    std::shared_ptr<ProfileTls> lookup_prof_tls (const char *name);
    std::shared_ptr<ProfileAuth> lookup_prof_auth (const char *name);
    std::shared_ptr<ProfileAlgDns> lookup_prof_alg_dns (const char *name);
    std::shared_ptr<ProfileScript> lookup_prof_script (const char *name);
    std::shared_ptr<ProfileRouting> lookup_prof_routing (const char *name);

    bool apply_tenant_config() override;

    bool upgrade_and_save();
    bool upgrade_schema(int upgrade_to_num);

    bool upgrade_by_version(std::string const& from);
    bool upgrade_to_0_9_23();

    bool load_internal();
    bool load_settings();
    bool load_captures();
    int  load_debug();
    int  load_db_address ();
    int  load_db_port ();
    int  load_db_proto ();
    int  load_db_policy ();
    int  load_db_prof_content ();
        int load_db_prof_content_subrules(libconfig::Setting& cur_object, ProfileContent* new_profile);
        bool load_db_prof_content_write_format(libconfig::Setting& cur_object, ProfileContent* new_profile);
    int  load_db_prof_detection ();
    int  load_db_tls_ca();
    int  load_db_prof_tls ();
    int  load_db_prof_auth ();
    int  load_db_prof_alg_dns ();
    int  load_db_routing ();
    int load_signatures(libconfig::Config &cfg, const char *name, SignatureTree &signature_tree, int preferred_index=-1);

    [[maybe_unused]]
    int  load_db_prof_script ();

    #ifdef USE_EXPERIMENT
    struct {
        bool enabled;
        std::string param;
    } experiment_1;
    int save_experiment(libconfig::Config& ex) const;
    bool load_experiment();
    #endif

    int save_captures(libconfig::Config& ex) const;

    bool new_address_object(libconfig::Setting& ex, std::string const& name) const;
    int save_address_objects(libconfig::Config& ex) const;

    bool new_port_object(libconfig::Setting& ex, std::string const& name) const;
    int save_port_objects(libconfig::Config& ex) const;

    bool new_proto_object(libconfig::Setting& section, std::string const& name) const;
    int save_proto_objects(libconfig::Config& ex) const;

    int save_debug(libconfig::Config& ex) const;

    bool new_detection_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_detection_profiles(libconfig::Config& ex) const;

    bool new_content_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_content_profiles(libconfig::Config& ex) const;

    bool new_tls_ca(libconfig::Setting& ex, std::string const& name) const;
    int save_tls_ca(libconfig::Config& ex) const;

    bool new_tls_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_tls_profiles(libconfig::Config& ex) const;

    bool new_alg_dns_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_alg_dns_profiles(libconfig::Config& ex) const;

    bool new_auth_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_auth_profiles(libconfig::Config& ex) const;

    bool new_policy(libconfig::Setting& ex, std::string const& name) const;
    int save_policy(libconfig::Config& ex) const;


    bool new_routing(libconfig::Setting& ex, std::string const& name) const;
    int save_routing(libconfig::Config& ex) const;

    enum class op_move { OP_MOVE_AFTER, OP_MOVE_BEFORE};
    bool move_policy(int what, int where, op_move op);

    [[nodiscard]] bool save_config() const;


    size_t cleanup_db_address ();
    size_t cleanup_db_port ();
    size_t cleanup_db_proto ();
    size_t cleanup_db_policy ();
    size_t cleanup_db_routing ();
    size_t cleanup_db_prof_content ();
    size_t cleanup_db_prof_detection ();
    size_t cleanup_db_tls_ca ();
    size_t cleanup_db_prof_tls ();
    size_t cleanup_db_prof_auth ();
    size_t cleanup_db_prof_alg_dns ();
    size_t cleanup_db_prof_script ();

    int policy_match (baseProxy *proxy);
    int policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right);
    int policy_action (int index);


    bool apply_config_change(std::string_view section);
    int policy_apply (baseHostCX *originator, baseProxy *proxy, int matched_policy=-1);
    std::shared_ptr<PolicyRule> lookup_policy(std::size_t i) { if(i < db_policy_list.size()) return db_policy_list.at(i); else return nullptr; }

    bool policy_apply_tls (int policy_num, baseCom *xcom);
    bool policy_apply_tls (const std::shared_ptr<ProfileTls> &pt, baseCom *xcom);

    bool prof_content_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileContent> &pc);
    bool prof_detect_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileDetection> &pd);

    std::optional<std::vector<std::string>> find_bypass_domain_hosts(std::string const& filter_element, bool wildcards_only);
    bool prof_tls_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileTls> &ps);
    bool prof_alg_dns_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileAlgDns>& p_alg_dns);
    [[maybe_unused]]
    bool prof_script_apply (baseHostCX *originator, baseProxy *new_proxy, const std::shared_ptr<ProfileScript>& p_script);

    static void gre_export_apply(traflog::PcapLog* pcaplog);

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

    try {
        std::string str_key(key);

        if (not str_key.empty() and s.exists(str_key)) {

            T tmp = s[str_key.c_str()];

            // Changed from this:
            // s.lookupValue(key, valref);
            // lookup value doesn't seem to work with empty strings ... :/

            valref = tmp;

            return true;
        }

    }
    catch(libconfig::SettingTypeException const& e) {
        static auto log = logan_lite("config");

        _war("cannot load: %s: %s", key, e.what());
    }

    return false;
}


#endif