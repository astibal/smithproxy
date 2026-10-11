#ifndef SMITHPROXY_EXPLICITPROXY_HPP
#define SMITHPROXY_EXPLICITPROXY_HPP

#include <proxy/mitmproxy.hpp>

class ExplicitProxyCX;
class PolicyRule;

// Common transport handoff for explicit proxy protocols.  Frontends parse
// their own request and prepare ExplicitProxyCX target state; this
// class owns the policy/routing/identity transition into a normal MitmProxy.
class ExplicitProxy : public MitmProxy {
public:
    using MitmProxy::MitmProxy;
    ~ExplicitProxy() override = default;

    void explicit_handoff(ExplicitProxyCX* cx);
    void handle_explicit_connect(ExplicitProxyCX* cx);
    void on_left_bytes(baseHostCX* cx) override;
    bool handle_cx_write(unsigned char side, baseHostCX* cx,
                         bool cross_direction_retry = false) override;
    bool handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx) override;
    int handle_sockets_once(baseCom* xcom) override;

    TYPENAME_OVERRIDE("ExplicitProxy")

protected:
    // A numeric policy index can refer to a different rule after reload.
    // Preserve the rule which authorized the explicit request until handoff.
    std::shared_ptr<PolicyRule> authorized_policy_;

private:
    bool send_pending_connect_response();

    std::string pending_connect_response_;
    std::string upstream_failure_response_;
    std::size_t pending_connect_response_offset_ = 0;
    bool connect_response_ready_ = false;
    bool close_after_connect_response_ = false;

    logan_lite log {"com.explicit.proxy"};
};

#endif // SMITHPROXY_EXPLICITPROXY_HPP
