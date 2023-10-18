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


#ifndef MITMPROXY_HPP
 #define MITMPROXY_HPP

#include <atomic>

#include <basecom.hpp>
#include <hostcx.hpp>

#include <proxy/socks5/sockshostcx.hpp>

#include <baseproxy.hpp>
#include <threadedacceptor.hpp>
#include <threadedreceiver.hpp>

#include <traflog/smcaplog.hpp>
#include <traflog/pcaplog.hpp>

#include <policy/policy.hpp>
#include <shm/shmauth.hpp>

#include <sslcertval.hpp>
#include <proxy/ocspinvoker.hpp>
#include <inspect/engine/http.hpp>

#include <utils/lazy_ptr.hpp>

struct whitelist_verify_entry {
};

class FilterProxy;


class IOController {
public:
    virtual ~IOController() = default;
    virtual void tap() = 0;
    virtual void untap() = 0;
    [[nodiscard]] IOController const* master() const noexcept { return (! master_) ?  this : master_; }
    void master(IOController* n) { master_ = n; }

private:
    IOController* master_ = nullptr ;
};

class MitmProxy : public baseProxy, public socle::sobject, public IOController {

    std::unique_ptr<socle::baseTrafficLogger> tlog_;
    
    bool identity_resolved_ = false;    // meant if attempt has been done, regardless of its result.
    std::unique_ptr<shm_logon_info_base> identity_;
    
    std::unique_ptr<std::vector<ProfileContentRule>> content_rule_; //save some space and store it as a pointer. Init it only when needed and delete in dtor.
    int matched_policy_ = -1;

    std::string replacement_msg;
    static inline long half_timeout_ = 5;
public:
    using whitelist_verify_entry_t = expiring<whitelist_verify_entry> ;
    using whitelist_map_t = ptr_cache<std::string,whitelist_verify_entry_t>;

    time_t half_holdtimer = 0;
    static long& half_timeout() { ; return half_timeout_; };

    static whitelist_map_t& whitelist_verify() {
        static whitelist_map_t m("whitelist_verify", 500, true, whitelist_verify_entry_t::is_expired);
        return m;
    }

    struct Opts_ContentWriter {
        bool write_payload = false;
    };
    lazy_ptr<Opts_ContentWriter> writer_opts_;
    lazy_ptr<Opts_ContentWriter>& writer_opts() {
        return writer_opts_;
    }

    struct Opts_Authentication {
        bool authenticate = false;
        bool resolve = false;
        bool block_identity = false;
    } auth_opts;

    // Remote filters - use other proxy to filter content of this proxy.
    // Elements are pair of "name" and pointer to the filter proxy 
    std::vector<std::pair<std::string, std::unique_ptr<FilterProxy>>> filters_;
    void add_filter(std::string const& name, FilterProxy* fp);
    
    // tap proxy - unmonitor all left and right sockets, pause contexts
    void tap_left();
    void tap_right();
    void tap() override;
    // untap proxy - monitor back again all L and R sockets, unpause contexts
    void untap_left();
    void untap_right();
    void untap() override;

    int matched_policy() const { return matched_policy_; }
    void matched_policy(int p)  { matched_policy_ = p; }

    void update_neighbors();

    inline bool identity_resolved() const { return identity_resolved_; }
    inline void identity_resolved(bool b) { identity_resolved_ = b; }

    shm_logon_info_base* identity() { return identity_.get(); }
    inline void identity(shm_logon_info_base const* new_id) { if(new_id) { identity_.reset(new_id->clone()); } }

    bool resolve_identity(bool insert_guest = false) { return resolve_identity(first_left(), insert_guest); }
    bool resolve_identity(baseHostCX* custom_cx, bool insert_guest);
    bool update_auth_ipX_map(baseHostCX*);
    bool apply_id_policies(baseHostCX* cx);
    std::optional<std::vector<std::string>> find_id_groups(baseHostCX const* cx);
    std::shared_ptr<ProfileSubAuth> find_auth_subprofile(std::vector<std::string> const& groups);


    std::unique_ptr<socle::baseTrafficLogger>& tlog() { return tlog_; }
    void toggle_tlog ();
    
    explicit MitmProxy(baseCom* c);
    ~MitmProxy() override;

    void proxy_dump_packet(side_t sid, buffer& buf);
    void proxy(baseHostCX* from, baseHostCX* to, side_t side, bool redirected);
    // this virtual method is called whenever there are new bytes in any LEFT host context!
    void on_left_bytes(baseHostCX* cx) override;
    void on_right_bytes(baseHostCX* cx) override;
    
    // ... and also when there is error on L/R side, claim the proxy DEAD. When marked dead, it will be safely 
    // closed by it's master proxy next cycle.

    // universal error handler
    void on_error(baseHostCX* cx, char side, const char* side_label);
    void on_left_error(baseHostCX* cx) override;
    void on_right_error(baseHostCX* cx) override;
    
    // check authentication status and return true if redirected
    virtual void on_half_close(baseHostCX* cx);

    bool handle_requirements(baseHostCX* cx);
    virtual bool handle_authentication(MitmHostCX* cx);
    virtual void handle_replacement_auth(MitmHostCX* cx);

#ifdef USE_EXPERIMENT
    std::atomic_bool ocsp_caller_tried {false};
    std::unique_ptr<AsyncOcspInvoker> ocsp_caller;
#endif

    //
    bool ssl_handled = false;
    // only once: check sslcom response and return true if redirected, set ssl_handled

    bool is_white_listed(MitmHostCX const* mh, SSLCom* peercom = nullptr);
    virtual bool handle_com_response_ssl(MitmHostCX* cx);
    virtual void handle_replacement_ssl(MitmHostCX* cx);

    static std::string verify_flag_string(int code);
    static std::string verify_flag_string_extended(int code);
    static std::string replacement_ssl_verify_detail(SSLCom* scom);

    static std::string replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest const* app_request, std::string const& more_info);
    void set_replacement_msg_ssl(SSLCom* scom); // evaluates SSL verify info and sets replacement_msg string
    
    // check if content has been pulled from cache and return true if so
    virtual bool handle_cached_response(MitmHostCX* cx);
    
    bool ask_destroy() override { state().dead(true); return true; };
    std::string to_string(int verbosity) const override;
    std::string to_connection_label(bool force_resolve = false) const;
    std::string to_connection_ID() const;
    std::optional<std::string> get_application() const;

    mutable bool wh_start = false;
    void webhook_session_start() const;

    mutable bool wh_stop = false;
    void webhook_session_stop() const;

    int handle_sockets_once(baseCom*) override;
    
    void init_content_replace();
    std::vector<ProfileContentRule>* content_rule() { return content_rule_.get(); }
    void content_replace(std::vector<ProfileContentRule> const& x) {
        for(auto const& i: x) {
            content_rule_->push_back(i);
        }
    }
    
    buffer content_replace_apply(const buffer &ref);
    
    void _debug_zero_connections(baseHostCX* cx);
    
    MitmHostCX* first_left() const;
    MitmHostCX* first_right() const;

    static std::atomic_uint64_t& current_sessions() { static std::atomic_uint64_t current; return current; };
    static std::atomic_uint64_t& total_sessions() { static std::atomic_uint64_t total; return total; };
    static socle::meter& total_mtr_up()  { static socle::meter t_up(12); return t_up; };
    static socle::meter& total_mtr_down() {static socle::meter t_down(12); return t_down; };


    TYPENAME_OVERRIDE("MitmProxy")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"proxy"};
    logan_lite log_dump {"proxy.payload"};
};

class MitmMasterProxy : public ThreadedAcceptorProxy<MitmProxy> {
public:
    
    MitmMasterProxy(baseCom* c, int worker_id, proxyType t = proxyType::transparent() ) :
        ThreadedAcceptorProxy< MitmProxy >(c,worker_id, t) {};
    
    baseHostCX* new_cx(int s) override;
    void on_left_new(baseHostCX* just_accepted_cx) override;
    int handle_sockets_once(baseCom* c) override;
    
    static inline bool ssl_autodetect = false;
    static inline bool ssl_autodetect_harder = true;

    bool detect_ssl_on_plain_socket(int sock);

private:
    logan_lite log {"com.tcp.acceptor"};
};


class MitmUdpProxy : public ThreadedReceiverProxy<MitmProxy> {
public:
    MitmUdpProxy(baseCom* c, int worker_id, proxyType t = proxyType::transparent() ):
        ThreadedReceiverProxy< MitmProxy >(c,worker_id, t) {};
    void on_left_new(baseHostCX* just_accepted_cx) override;
    baseHostCX* new_cx(int s) override;

private:
    logan_lite log {"com.udp.acceptor"};
};


std::string whitelist_make_key_l4(baseHostCX const* cx);
std::string whitelist_make_key_cert(baseHostCX const* cx);

#endif //MITMPROXY_HPP
