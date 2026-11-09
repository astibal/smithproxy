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
#include <optional>
#include <utility>
 
#include <libconfig.h++>
#include <ext/libcidr/cidr.hpp>
#include <ranges.hpp>
#include <policy/policy.hpp>
#include <sslcom.hpp>
#include <traflog/pcaplog.hpp>

#include "cfg_update.hpp"
#include "cfg_archive.hpp"
#include "cfg_archive_monitor.hpp"
#include "cfg_archive_restore.hpp"
#include "cfg_resource_write.hpp"
#include "cfg_runtime_tree.hpp"
#include "cfg_write_gate.hpp"
#include "cfg_tx_validate.hpp"
#include <service/reload/file_reload_service.hpp>

namespace sx::cfg {
struct SaveResult;
}





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

struct SignatureTree;

struct DNS_Setup {

    static AddressInfo const& default_ns();
    static AddressInfo const& choose_dns_server(int pref_family);

private:
    static AddressInfo create_default_ns(int fam, const char* ip, unsigned short port);
};


class CfgFactory : public CfgFactoryBase {

    // Adapts the factory-owned archive cache and persistence boundary to the
    // narrow interface required by CfgResourceWriter. CfgFactory owns this
    // collaborator; it is not itself a resource archive.
    class ArchiveStorage final : public sx::cfg::CfgArchiveStorage {
    public:
        explicit ArchiveStorage(CfgFactory& owner): owner_(owner) {}

        // Report whether the factory currently owns a writable native archive.
        [[nodiscard]] bool available() const override;
        // Return the exact native archive bytes used as the write base.
        [[nodiscard]] std::string current() const override;
        // Replace smithproxy.cfg in an isolated archive copy.
        [[nodiscard]] sx::cfg::CfgSaveData prepare_main(
            std::string content) const override;
        // Apply one resource edit to an isolated archive copy.
        [[nodiscard]] sx::cfg::CfgSaveData prepare_resource(
            std::string path,
            std::optional<std::string> content,
            bool executable) const override;
        // Publish and adopt the candidate without exposing a partial state.
        [[nodiscard]] bool publish(
            const sx::cfg::CfgSaveData& prepared) const override;

    private:
        CfgFactory& owner_;
    };

    libconfig::Config cfgapi;
    // Describes the persistent bytes backing cfgapi. Keeping source policy
    // beside the parsed config prevents save and backup paths from guessing
    // whether config_file names a legacy text file or a native archive. It is
    // mutable because the historically const save_config() advances the cached
    // archive only after durable replacement succeeds.
    mutable std::optional<sx::cfg::CfgArchive> config_archive_;
    // A restored archive is the next startup configuration, while cfgapi still
    // describes the running process. Block ordinary saves until restart so the
    // explicitly restored bytes cannot be overwritten by that older state.
    mutable bool startup_archive_pending_ = false;
    // Own the materialized runtime view of resources selected at startup.
    std::optional<sx::cfg::CfgRuntimeTree> runtime_tree_;
    // The shared reload worker observes persistent CFtar generations without
    // ever applying them to the running configuration.
    std::shared_ptr<sx::cfg::CfgArchiveMonitor> archive_monitor_;
    sx::reload::FileReloadService archive_monitor_service_;
    sx::reload::FileReloadService::resource_id archive_monitor_id_ {0};
    std::recursive_mutex lock_;
    ArchiveStorage archive_storage_;

    static inline std::shared_ptr<CfgFactory> self;
    static inline std::shared_ptr<UpdateBoard> update_board;
    static inline std::shared_ptr<sx::cfg::CfgWriteGate> write_gate_;

public:
    // Each version bump implies a config upgrade - we start on 1000
    // see upgrade_schema() - control config upgrade
    constexpr static inline const int SCHEMA_VERSION  = 1050;

    static inline std::atomic_bool LOAD_ERRORS = false;
    static constexpr std::string_view CT_UNAVAILABLE_WARNING =
        "Certificate Transparency is enabled by policy, but the CT log list is "
        "unavailable. CT validation remains FAIL-CLOSED.";

    CfgFactory(): archive_storage_(*this) {}
    CfgFactory(CfgFactory const &) = delete;
    void operator=(const CfgFactory&) = delete;
    ~CfgFactory() override {
        archive_monitor_service_.stop();
        cleanup();
    }

    static void init() {
        self = std::make_shared<CfgFactory>();
        update_board = std::make_shared<UpdateBoard>();
        write_gate_ = std::make_shared<sx::cfg::CfgWriteGate>();
    }

    static std::shared_ptr<CfgFactory> get() {
        return CfgFactory::self;
    }

    static std::shared_ptr<UpdateBoard> board() {
        return CfgFactory::update_board;
    }


    static std::recursive_mutex& lock() { return get()->lock_; }
    static std::shared_ptr<sx::cfg::CfgWriteGate> write_gate() { return write_gate_; }
    // Persist the current running configuration into its native startup archive.
    static sx::cfg::SaveResult save_running(
        std::string const& expected_revision,
        std::string const& source);
    // Validate and atomically install an uploaded archive for the next restart.
    static sx::cfg::ArchiveRestoreResult restore_startup_archive(
        std::string const& expected_revision,
        std::string const& expected_hash,
        std::string const& payload);
    // Replace one native archive resource without changing the running process.
    static sx::cfg::ResourceWriteResult write_archive_resource(
        std::string expected_revision,
        std::string expected_archive_hash,
        std::string path,
        std::optional<std::string> content,
        bool executable = false);
    static sx::cfg::tx::Transaction::CreateResult make_transaction(std::string owner) {
        auto factory = get();
        return sx::cfg::tx::Transaction::create(
            *board(),
            *write_gate(),
            lock(),
            std::move(owner),
            [factory](std::string const& snapshot) {
                return factory->apply_snapshot(snapshot);
            });
    }
    static sx::cfg::tx::Transaction::CreateResult make_transaction(
        std::string owner,
        std::string base_revision) {
        auto factory = get();
        return sx::cfg::tx::Transaction::create(
            *board(),
            *write_gate(),
            lock(),
            std::move(owner),
            std::move(base_revision),
            [factory](std::string const& snapshot) {
                return factory->apply_snapshot(snapshot);
            });
    }
    sx::cfg::tx::Result<sx::cfg::tx::Committed> commit_new_entry(
        sx::cfg::tx::Transaction& transaction,
        std::string const& section,
        std::string const& entry_name,
        std::string description);
    sx::cfg::tx::Result<sx::cfg::tx::Prepared> prepare_operations(
        sx::cfg::tx::Transaction& transaction,
        std::vector<sx::cfg::tx::Op> operations);
    static libconfig::Setting& cfg_root() { return get()->cfgapi.getRoot(); }
    static libconfig::Config&  cfg_obj() { return get()->cfgapi; }

    [[nodiscard]] bool ct_requested() const;

    loglevel args_debug_flag = NON;

    std::string internal_version;
    int         schema_version = SCHEMA_VERSION;

    std::string listen_tcp_port_base = "50080";
    std::string listen_tls_port_base = "50443";
    std::string listen_dtls_port_base = "50443";
    std::string listen_quic_port_base = "443";
    std::string listen_udp_port_base = "50080";
    std::string listen_socks_port_base = "1080";
    std::string listen_http_connect_port_base = "3128";

    std::string listen_tcp_port = "50080";
    std::string listen_tls_port = "50443";
    std::string listen_dtls_port = "50443";
    std::string listen_quic_port = "443";
    std::string listen_udp_port = "50080";
    std::string listen_socks_port = "1080";
    std::string listen_http_connect_port = "3128";

    // Preserve user-facing resource settings independently from temporary
    // runtime materialization. Saving must never publish a /tmp archive view.
    std::string configured_certs_path;
    std::string configured_ca_bundle_path;
    std::string configured_ca_bundle_file;
    std::string dir_msg_templates;

    bool config_file_check_only = false;

    bool accept_tproxy = true;
    bool accept_redirect = true;
    bool accept_socks = true;
    bool accept_http_connect = false;
    bool accept_api = true;
    bool policy_fail_open = false;
    bool policy_access_request_fail_open = false;
    bool extended_local_destination_protection = true;

    std::string admin_group;

    int num_workers_tcp = 0;
    int num_workers_tls = 0;
    int num_workers_dtls = 0;
    int num_workers_quic = -1;
    int num_workers_udp  = 0;
    int num_workers_socks = 0;
    int num_workers_http_connect = 0;

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
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_ssh);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_tls_ca);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_auth);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_alg_dns);
    DB_MAP(std::shared_ptr<CfgElement>, db_prof_script);

    DB_MAP(std::shared_ptr<CfgElement>, db_features);

    mp::vector<int> db_udp_quick_ports;


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
        // GRE carries either reconstructed plaintext or serialized PCAPNG blocks.
        std::string gre_format = "traffic";
        std::string tun_dst = "127.0.0.1";
        int tun_ttl {1};
        std::string bind_interface;
    } capture_remote;

    struct settings_webhook_t {
        bool enabled = false;
        std::string cfg_url;
        bool cfg_tls_verify = true;
        bool sift = false;
        std::string sift_url = "http://127.0.0.1:18081/webhook";
        std::string sift_tenant_id = "default";
        std::string sift_instance_id;
        int sift_payload_limit_per_direction = 256 * 1024;
        std::string sift_lored_mode = "disabled";
        bool sift_lored_include_url = false;

        bool allow_api_override = false;
        struct {
            std::string url;
            bool tls_verify = true;
            expiring_int timeout = expiring_int(66,0);
        } override;

        [[nodiscard]] std::string const& active_url() const {
            if(allow_api_override and not override.timeout.expired() and not override.url.empty()) {
                return override.url;
            }
            return cfg_url;
        };
        [[nodiscard]] bool active_tls_verify() const {
            if(allow_api_override and not override.timeout.expired() and not override.url.empty()) {
                return override.tls_verify;
            }
            return cfg_tls_verify;
        };

        static inline int DEFAULT_PING_INTERVAL = 120;
        static inline int DEFAULT_NBR_UPDATE_INTERVAL = 60*15; // default: 15 minutes tag update interval
        static inline int DEFAULT_NBR_UPDATE_REFRESH_AGE = 60*5; // default: 5 minutes tag update interval

        std::string hostid;
        std::string bind_interface;
        int ping_interval = DEFAULT_PING_INTERVAL;
        int nbr_update_interval = DEFAULT_NBR_UPDATE_INTERVAL;
        int nbr_tag_refresh_age = DEFAULT_NBR_UPDATE_REFRESH_AGE;
    } settings_webhook;

    std::vector<AddressInfo> db_nameservers;

    // Select and load a native archive or an explicit legacy configuration path.
    bool cfgapi_init(const char* fnm);
    // Load the parsed configuration from an already validated archive source.
    bool cfgapi_init(sx::cfg::CfgArchive source);

    // Re-open the same logical source for reload. A native archive is parsed
    // and validated again; an explicit legacy path remains explicit.
    sx::cfg::CfgArchive reload_source();

    // Resolve a persistent resource against the source selected for the
    // running configuration. The returned value owns native bytes or the
    // explicit legacy path, so it remains valid after this method unlocks.
    sx::cfg::CfgResource resolve_resource(std::string logical_path,
                                          std::string legacy_path);

    // Resolve a named directory as individual resources. Native archives must
    // contain every requested entry; an explicit legacy source remains the
    // only mode in which the directory path is consulted.
    std::map<std::string, std::string> native_resources(
        std::string logical_dir, std::string legacy_dir,
        const std::vector<std::string>& names);

    // List stored native resources without assigning them runtime semantics.
    // In particular, commands/ entries remain inert until an explicit caller
    // requests and authorizes an action in a later feature.
    std::vector<std::string> resources(std::string_view logical_dir);

    // Return a content-free administrative inventory of the active persistent
    // configuration source.
    sx::cfg::CfgArchiveInfo archive_info();

    // Report whether the active source is the native archive rather than an
    // explicitly selected legacy source used during migration or tenant startup.
    bool using_native_archive() const;

    // Serialize the active native archive exactly as it would be persisted.
    // Legacy sources fail explicitly because they are not complete CFtar
    // configuration bundles.
    std::string archive_payload();

    // Read and validate the recovery archive through the privileged file
    // capability. The returned bytes are suitable for an exact download.
    std::string previous_archive_payload();

    // Read one validated resource from the active native archive.
    std::string archive_resource(std::string const& path);

    // Materialize the active archive resources into a protected runtime tree.
    std::string materialize_runtime_archive();

    // Project native directory-backed resources into a private runtime tree;
    // legacy sources retain their configured filesystem paths unchanged.
    void apply_runtime_resource_paths();

    // True after a successful restore that deliberately requires a process
    // restart, or after an external CFtar replacement is observed.
    [[nodiscard]] bool startup_archive_pending() const;
    // Start persistent archive observation after privilege separation is ready.
    void start_archive_monitor();
    // Return the latest external archive observation error, if any.
    [[nodiscard]] std::string archive_monitor_error() const;
    void  cleanup();

    static void cfg_clone_setting(libconfig::Setting& dst, libconfig::Setting& orig, int index = -1 );
    static int cfg_write(libconfig::Config& cfg, FILE* where, unsigned long iobufsz = 0);

    static std::pair<bool, std::string> cfg_add_prepare_params(std::string const& section, std::vector<std::string>& args);
    std::pair<bool, std::string> cfg_add_entry(std::string const& section_name, std::string const& entry_name);
    bool build_new_entry(libconfig::Setting& collection,
                         std::string const& section,
                         std::string const& entry_name) const;
    [[nodiscard]] bool supports_new_entry(std::string const& section) const;
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
    std::shared_ptr<CfgString> lookup_features (const char *name);
    std::shared_ptr<ProfileDetection> lookup_prof_detection (const char *name);
    std::shared_ptr<ProfileContent> lookup_prof_content (const char *name);
    std::shared_ptr<ProfileTls> lookup_prof_tls (const char *name);
    std::shared_ptr<ProfileSsh> lookup_prof_ssh (const char *name);
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
    int  load_db_features ();
    int  load_db_policy ();
    int  load_db_prof_content ();
        int load_db_prof_content_subrules(libconfig::Setting& cur_object, ProfileContent* new_profile);
        bool load_db_prof_content_write_format(libconfig::Setting& cur_object, ProfileContent* new_profile);
    int  load_db_prof_detection ();
    int  load_db_tls_ca();
    int  load_db_prof_tls ();
    int  load_db_prof_ssh ();
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

    bool new_ssh_profile(libconfig::Setting& ex, std::string const& name) const;
    int save_ssh_profiles(libconfig::Config& ex) const;

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
    [[nodiscard]] std::optional<std::string> snapshot() const;
    [[nodiscard]] bool replace_config(std::string const& snapshot);
    [[nodiscard]] bool apply_config(bool reload);
    [[nodiscard]] sx::cfg::tx::Result<void> apply_snapshot(
        std::string const& snapshot);
    // The caller holds a write-gate guard from before the mutation.
    [[nodiscard]] bool record_revision(std::string const& source,
                                       std::string description) const;

private:
    // Replace the monitored generation after a configuration source is loaded.
    void configure_archive_monitor_locked();
    // Advance the monitor after Smithproxy successfully publishes known bytes.
    void accept_archive_monitor(std::string_view payload) const;
    // Read the lock-free external-change signal while the config lock is held.
    [[nodiscard]] bool external_archive_change_locked() const;

public:


    size_t cleanup_db_address ();
    size_t cleanup_db_port ();
    size_t cleanup_db_proto ();
    size_t cleanup_db_policy ();
    size_t cleanup_db_routing ();
    size_t cleanup_db_prof_content ();
    size_t cleanup_db_prof_detection ();
    size_t cleanup_db_tls_ca ();
    size_t cleanup_db_prof_tls ();
    size_t cleanup_db_prof_ssh ();
    size_t cleanup_db_prof_auth ();
    size_t cleanup_db_prof_alg_dns ();
    size_t cleanup_db_prof_script ();

    std::shared_ptr<PolicyRule>policy_rule(int index);
    int policy_match (baseProxy *proxy);
    int policy_match (std::vector<baseHostCX *> &left, std::vector<baseHostCX *> &right);
    int policy_action (int index);


    bool apply_config_change(std::string_view section);
    int policy_apply (baseHostCX *originator, MitmProxy *proxy, int matched_policy=-1);
    void policy_apply_features(std::shared_ptr<PolicyRule> const& policy_rule, MitmProxy *mitm_proxy);
    std::shared_ptr<PolicyRule> lookup_policy(std::size_t i) {
        std::scoped_lock<std::recursive_mutex> guard(lock_);
        return i < db_policy_list.size() ? db_policy_list.at(i) : nullptr;
    }

    bool policy_apply_tls (int policy_num, baseCom *xcom);
    bool policy_apply_tls (const std::shared_ptr<ProfileTls> &pt, baseCom *xcom);

    bool prof_content_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileContent> &pc);
    bool prof_detect_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileDetection> &pd);

    std::optional<std::vector<std::string>> find_bypass_domain_hosts(std::string const& filter_element, bool wildcards_only);
    bool prof_tls_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileTls> &ps);
    bool prof_alg_dns_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileAlgDns>& p_alg_dns);
    [[maybe_unused]]
    bool prof_script_apply (baseHostCX *originator, MitmProxy *new_proxy, const std::shared_ptr<ProfileScript>& p_script);

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

template <class T>
bool load_if_exists_atomic(libconfig::Setting const& s, const char* key, T& valref) {

    try {
        std::string str_key(key);

        if (not str_key.empty() and s.exists(str_key)) {
            valref.store(s[str_key.c_str()]);

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
