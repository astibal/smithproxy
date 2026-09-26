#ifndef SMITHPROXY_EXPLICITPROXY_HPP
#define SMITHPROXY_EXPLICITPROXY_HPP

#include <proxy/mitmproxy.hpp>

class socksServerCX;

// Common transport handoff for explicit proxy protocols.  Frontends parse
// their own request and prepare socksServerCX-compatible target state; this
// class owns the policy/routing/identity transition into a normal MitmProxy.
class ExplicitProxy : public MitmProxy {
public:
    using MitmProxy::MitmProxy;
    ~ExplicitProxy() override = default;

    void explicit_handoff(socksServerCX* cx);
    void handle_explicit_connect(socksServerCX* cx);
    bool explicit_handoff_resolve_identity(MitmHostCX* cx);
    bool explicit_handoff_authenticate(MitmHostCX* cx);
    void on_left_bytes(baseHostCX* cx) override;

    TYPENAME_OVERRIDE("ExplicitProxy")

private:
    logan_lite log {"com.explicit.proxy"};
};

#endif // SMITHPROXY_EXPLICITPROXY_HPP
