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
#include <inspect/http1engine.hpp>


struct whitelist_verify_entry {
};

typedef expiring<whitelist_verify_entry> whitelist_verify_entry_t;

class FilterProxy;


class IOController {
public:
    virtual void tap() = 0;
    virtual void untap() = 0;
    [[nodiscard]] IOController const* master() const noexcept { return (! master_) ?  this : master_; }
    void master(IOController* n) { master_ = n; }

private:
    IOController* master_ = nullptr ;
};

class MitmProxy : public baseProxy, public socle::sobject, public IOController {

protected:
    std::unique_ptr<socle::baseTrafficLogger> tlog_;
    
    bool identity_resolved_ = false;    // meant if attempt has been done, regardless of its result.
    shm_logon_info_base* identity_ = nullptr;
    
    std::vector<ProfileContentRule>* content_rule_ = nullptr; //save some space and store it as a pointer. Init it only when needed and delete in dtor.
    int matched_policy_ = -1;

    std::string replacement_msg;
public: 
    time_t half_holdtimer = 0;
    static long& half_timeout() { static long s_half_timetout = 5; return s_half_timetout; };

    using whitelist_map = ptr_cache<std::string,whitelist_verify_entry_t>;
    static whitelist_map& whitelist_verify() {
        static whitelist_map m("whitelist - verify", 500, true, whitelist_verify_entry_t::is_expired);
        return m;
    }

    struct Opts_ContentWriter {
        bool write_payload = false;
        ContentCaptureFormat format;
        long long pcap_single_quota;
    };
    std::unique_ptr<Opts_ContentWriter> writer_opts_;
    Opts_ContentWriter* writer_opts() {
        if(not writer_opts_) writer_opts_ = std::make_unique<Opts_ContentWriter>();
        return writer_opts_.get();
    }


    bool opt_auth_authenticate = false;
    bool opt_auth_resolve = false;
    bool auth_block_identity = false;
    
    
    // Remote filters - use other proxy to filter content of this proxy.
    // Elements are pair of "name" and pointer to the filter proxy 
    std::vector<std::pair<std::string,FilterProxy*>> filters_;
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
    
    inline bool identity_resolved() const;
    inline void identity_resolved(bool b);
    shm_logon_info_base* identity() { return identity_; }
    inline void identity(shm_logon_info_base* i) { delete identity_; if(i != nullptr) { identity_ = i->clone(); } }
    bool resolve_identity(baseHostCX*,bool);
    bool update_auth_ipX_map(baseHostCX*);
    bool apply_id_policies(baseHostCX* cx);
   

    
    std::unique_ptr<socle::baseTrafficLogger>& tlog() { return tlog_; }
    void toggle_tlog ();
    
    explicit MitmProxy(baseCom* c);
    ~MitmProxy() override;

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
    virtual bool handle_authentication(MitmHostCX* cx);
    virtual void handle_replacement_auth(MitmHostCX* cx);

    std::atomic_bool ocsp_caller_tried {false};
    std::unique_ptr<AsyncOcspInvoker> ocsp_caller;

    //
    bool ssl_handled = false;
    // only once: check sslcom response and return true if redirected, set ssl_handled
    virtual bool handle_com_response_ssl(MitmHostCX* cx);
    virtual void handle_replacement_ssl(MitmHostCX* cx);

    static std::string verify_flag_string(int code);
    static std::string verify_flag_string_extended(int code);
    static std::string replacement_ssl_verify_detail(SSLCom* scom);

    static std::string replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest* app_request, std::string const& more_info);
    void set_replacement_msg_ssl(SSLCom* scom); // evaluates SSL verify info and sets replacement_msg string
    
    // check if content has been pulled from cache and return true if so
    virtual bool handle_cached_response(MitmHostCX* cx);
    
    bool ask_destroy() override { state().dead(true); return true; };
    std::string to_string(int verbosity) const override;
    
    int handle_sockets_once(baseCom*) override;
    
    void init_content_replace();
    std::vector<ProfileContentRule>* content_rule() { return content_rule_; }    
    void content_replace(std::vector<ProfileContentRule>& x) { 
	for(auto const& i: x) {
	    content_rule_->push_back(i);
	}
    }
    
    buffer content_replace_apply(buffer);
    
    void _debug_zero_connections(baseHostCX* cx);
    
    MitmHostCX* first_left();
    MitmHostCX* first_right();
    
public:

    static std::atomic_uint64_t& total_sessions() { static std::atomic_uint64_t total; return total; };
    static socle::meter& total_mtr_up()  { static socle::meter t_up(12); return t_up; };
    static socle::meter& total_mtr_down() {static socle::meter t_down(12); return t_down; };

    
    TYPENAME_OVERRIDE("MitmProxy")
    DECLARE_LOGGING(to_string)

private:
    logan_attached<MitmProxy> log;
};

class MitmMasterProxy : public ThreadedAcceptorProxy<MitmProxy> {
public:
    
    MitmMasterProxy(baseCom* c, int worker_id, proxyType t = proxyType::transparent() ) :
        ThreadedAcceptorProxy< MitmProxy >(c,worker_id, t) {

        log.area("acceptor.tcp");
    };
    
    baseHostCX* new_cx(int s) override;
    void on_left_new(baseHostCX* just_accepted_cx) override;
    int handle_sockets_once(baseCom* c) override;
    
    static bool ssl_autodetect;
    static bool ssl_autodetect_harder;
    bool detect_ssl_on_plain_socket(int sock);
    
    time_t auth_table_refreshed = 0;

};


class MitmUdpProxy : public ThreadedReceiverProxy<MitmProxy> {
public:
    MitmUdpProxy(baseCom* c, int worker_id, proxyType t = proxyType::transparent() ):
        ThreadedReceiverProxy< MitmProxy >(c,worker_id, t) {

        log.area("acceptor.udp");
    };
    void on_left_new(baseHostCX* just_accepted_cx) override;
    baseHostCX* new_cx(int s) override;
};


std::string whitelist_make_key(MitmHostCX*);

#endif //MITMPROXY_HPP
