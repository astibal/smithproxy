#ifndef SMITHPROXY_HTTPCONNECT_HPP
#define SMITHPROXY_HTTPCONNECT_HPP

#include <proxy/socks5/socksproxy.hpp>
#include <proxy/httpconnect/httpconnectrequest.hpp>

#include <string_view>

class HttpConnectServerCX : public socksServerCX {
public:
    using socksServerCX::socksServerCX;

    std::size_t process_in() override;
    std::size_t process_socks_reply() override;
    void pre_write() override;

    TYPENAME_OVERRIDE("httpConnectServerCX")

private:
    void send_error(unsigned int status, std::string_view reason);

    bool close_after_reply_ = false;
    logan_lite log {"com.http-connect"};
};

class HttpConnectProxy : public ExplicitProxy {
public:
    using ExplicitProxy::ExplicitProxy;

    void on_left_message(baseHostCX* cx) override;

    std::string to_string(int lev) const override;

    TYPENAME_OVERRIDE("HttpConnectProxy")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"com.http-connect.proxy"};
};

class MitmHttpConnectProxy : public ThreadedAcceptorProxy<HttpConnectProxy> {
public:
    MitmHttpConnectProxy(baseCom* c, int worker_id,
                         proxyType t = proxyType::proxy())
        : ThreadedAcceptorProxy<HttpConnectProxy>(c, worker_id, t) {}

    baseHostCX* new_cx(int s) override;
    void on_left_new(baseHostCX* just_accepted_cx) override;

    TYPENAME_OVERRIDE("MitmHttpConnectProxy")

private:
    logan_lite log {"com.http-connect.acceptor"};
};

#endif // SMITHPROXY_HTTPCONNECT_HPP
