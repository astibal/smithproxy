#ifndef SMITHPROXY_HTTPCONNECT_HPP
#define SMITHPROXY_HTTPCONNECT_HPP

#include <proxy/master_policy.hpp>
#include <proxy/explicitproxy.hpp>
#include <proxy/proxy_hooks.hpp>
#include <proxy/explicitproxycx.hpp>
#include <proxy/httpconnect/httpconnectrequest.hpp>
#include <service/core/sessionlist.hpp>

#include <atomic>
#include <string>
#include <string_view>

class HttpConnectServerCX : public ExplicitProxyCX {
public:
    static inline std::atomic_bool proxy_authorization{false};

    HttpConnectServerCX(baseCom* c, unsigned int s);

    std::size_t process_in() override;
    std::size_t process_proxy_reply() override;
    std::string_view upstream_success_response() const override;
    std::string_view upstream_failure_response() const override;
    std::string_view upstream_policy_failure_response() const override;
    void pre_write() override;

    TYPENAME_OVERRIDE("httpConnectServerCX")

private:
    struct Authentication {
        bool accepted = false;
        std::string response;
    };

    Authentication authenticate_request(std::string_view headers,
                                        const HttpConnectRequest& target);

    void send_error(unsigned int status, std::string_view reason);
    void send_response(std::string response);

    bool close_after_reply_ = false;
    logan_lite log {"com.http-connect"};
};

class HttpConnectProxy : public ExplicitProxy {
public:
    using ExplicitProxy::ExplicitProxy;
    ~HttpConnectProxy() override = default;
    void shutdown() override;

    sx::proxy::ProxyHooks::HttpConnectDecision connect_request(
        HttpConnectServerCX& client, std::string_view request,
        const HttpConnectRequest& target, bool authenticated, std::string_view response);
    void connect_response(std::string& response, bool connected) override;

    void on_left_message(baseHostCX* cx) override;

    std::string to_string(int lev) const override;

    TYPENAME_OVERRIDE("HttpConnectProxy")
    DECLARE_LOGGING(to_string)

private:
    void connect_cleanup();

    HttpConnectRequest connect_target_;
    bool connect_observed_ = false;
    bool connect_finished_ = false;
    bool authentication_denied_ = false;
    logan_lite log {"com.http-connect.proxy"};
};

class MitmHttpConnectProxy : public ThreadedAcceptorProxy<HttpConnectProxy>,
                             public SessionListConsumer {
public:
    sx::proxy::policy_state_t policy_state;

    MitmHttpConnectProxy(baseCom* c, int worker_id,
                         proxyType t = proxyType::proxy())
        : ThreadedAcceptorProxy<HttpConnectProxy>(c, worker_id, t) {}

    baseHostCX* new_cx(int s) override;
    void on_left_new(std::unique_ptr<baseHostCX> accepted_cx) override;
    int handle_sockets_once(baseCom* c) override;
    bool run_timers() override;

    TYPENAME_OVERRIDE("MitmHttpConnectProxy")

private:
    logan_lite log {"com.http-connect.acceptor"};
};

#endif // SMITHPROXY_HTTPCONNECT_HPP
