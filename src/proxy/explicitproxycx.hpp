#ifndef SMITHPROXY_EXPLICITPROXYCX_HPP
#define SMITHPROXY_EXPLICITPROXYCX_HPP

#include <proxy/mitmhost.hpp>
#include <async/asyncdns.hpp>
#include <socketinfo.hpp>

using explicit_state = enum class explicit_state_ {
    INIT = 1u, HELLO_SENT, WAIT_REQUEST, REQ_RECEIVED, WAIT_POLICY,
    POLICY_RECEIVED, REQRES_SENT, DNS_QUERY_SENT, DNS_RESP_RECV,
    DNS_RESP_FAILED, HANDOFF, ZOMBIE
};
using explicit_request_error = enum class explicit_request_error_ {
    NONE = 0, UNSUPPORTED_VERSION, UNSUPPORTED_ATYPE, UNSUPPORTED_METHOD,
    MALFORMED_DATA, UNAUTHORIZED
};
using explicit_policy = enum class explicit_policy_ { PENDING, ACCEPT, REJECT };

class ExplicitProxyCX : public MitmHostCX, public epoll_handler {
public:
    ExplicitProxyCX(baseCom* c, unsigned int s);
    ~ExplicitProxyCX() override = default;

    bool is_ssl = false;
    bool tested_dns_a = false;
    bool tested_dns_aaaa = false;
    static inline bool mixed_ip_versions = true;
    static inline bool prefer_ipv6 = false;
    static bool global_async_dns;

    virtual std::size_t process_proxy_reply() = 0;
    virtual std::string_view upstream_success_response() const { return {}; }
    virtual std::string_view upstream_failure_response() const { return {}; }

    virtual bool setup_target();
    explicit_request_error prepare_connect_target(std::string const& host,
                                                   unsigned short port);

    void wait_policy();
    void pre_write() override;
    bool new_message() const override;
    virtual void verdict(explicit_policy);
    void state(explicit_state s) { state_ = s; }

    explicit_request_error request_error_ = explicit_request_error::NONE;
    explicit_policy verdict_ = explicit_policy::PENDING;
    explicit_state state_ = explicit_state::INIT;

    std::unique_ptr<MitmHostCX> left;
    std::unique_ptr<MitmHostCX> right;

    void handle_event(baseCom*) override;

protected:
    explicit_request_error resolve_connect_target();
    std::string req_str_addr;
    unsigned short req_port = 0;
    std::size_t req_hdr_size = 0;

private:
    using dns_response_t = std::pair<std::shared_ptr<DNS_Response>, ssize_t>;
    void setup_dns_async(std::string const& fqdn, DNS_Record_Type type,
                         AddressInfo const& nameserver);
    void dns_response_callback(dns_response_t const& resp);
    bool process_dns_response(std::shared_ptr<DNS_Response> resp);
    bool choose_server_ip(std::vector<std::string>& target_ips);

    bool async_dns_ = true;
    std::unique_ptr<AsyncDnsQuery> async_dns_query_;

    logan_lite log {"com.explicit.cx"};
};

#endif
