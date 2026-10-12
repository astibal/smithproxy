#ifndef SMITHPROXY_EXPLICITPROXYCX_HPP
#define SMITHPROXY_EXPLICITPROXYCX_HPP

#include <proxy/mitmhost.hpp>
#include <async/asyncdns.hpp>
#include <socketinfo.hpp>
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <optional>
#include <unordered_set>

namespace sx::explicit_proxy {
    // baseCom reserves zero as its "no descriptor" sentinel. DNSFactory
    // promotes a raw fd 0 before handing a query to this event-loop path.
    inline bool valid_dns_socket(int fd) { return fd > 0; }

    inline bool is_unspecified_address(std::string_view text) noexcept {
        if(text.empty() || text.size() >= INET6_ADDRSTRLEN) return false;
        std::array<char, INET6_ADDRSTRLEN> terminated {};
        std::memcpy(terminated.data(), text.data(), text.size());

        in_addr v4 {};
        if(::inet_pton(AF_INET, terminated.data(), &v4) == 1)
            return v4.s_addr == htonl(INADDR_ANY);
        in6_addr v6 {};
        return ::inet_pton(AF_INET6, terminated.data(), &v6) == 1 &&
               IN6_IS_ADDR_UNSPECIFIED(&v6);
    }

    inline std::vector<std::string> fresh_dns_addresses(
            std::shared_ptr<DNS_Response> const& response,
            std::time_t now = std::time(nullptr)) {
        std::vector<std::string> addresses;
        if (!response || response->questions().size() != 1 ||
            response->questions().front().rec_class != 1 ||
            response->answers().empty() ||
            (response->flags() & 0x0200U) != 0 ||
            (response->flags() & 0x000fU) != 0)
            return addresses;

        auto normalize = [](std::string_view value) {
            while(!value.empty() && value.back() == '.') value.remove_suffix(1);
            std::string result(value);
            std::transform(result.begin(), result.end(), result.begin(),
                           [](unsigned char c) {
                               return static_cast<char>(std::tolower(c));
                           });
            return result;
        };
        std::unordered_set<std::string> permitted_names;
        permitted_names.insert(normalize(response->questions().front().rec_str));
        const auto age = now > response->loaded_at
            ? static_cast<std::uint64_t>(now - response->loaded_at) : 0U;
        for(std::size_t pass = 0; pass < response->answers().size(); ++pass) {
            bool changed = false;
            for(auto const& answer : response->answers()) {
                if(answer.class_ != 1 || answer.type_ != CNAME ||
                   answer.ttl_ == 0 || age >= answer.ttl_ ||
                   answer.rdata_name_.empty() ||
                   permitted_names.count(normalize(answer.qname_)) == 0) {
                    continue;
                }
                changed |= permitted_names.insert(
                    normalize(answer.rdata_name_)).second;
            }
            if(!changed) break;
        }

        const auto requested_type = response->questions().front().rec_type;
        for (auto const& answer : response->answers()) {
            if(answer.class_ != 1 || answer.type_ != requested_type ||
               (answer.type_ != A && answer.type_ != AAAA) ||
               permitted_names.count(normalize(answer.qname_)) == 0) {
                continue;
            }
            if(answer.ttl_ == 0 || age >= answer.ttl_)
                continue;
            if (auto address = answer.ip(false); !address.empty())
                addresses.push_back(std::move(address));
        }
        return addresses;
    }

    inline std::optional<DNS_Record_Type> next_dns_retry(
            bool mixed_ip_versions, bool tested_a, bool tested_aaaa) {
        if (!mixed_ip_versions)
            return std::nullopt;
        if (!tested_aaaa)
            return AAAA;
        if (!tested_a)
            return A;
        return std::nullopt;
    }

    inline std::vector<DNS_Record_Type> dns_query_order(
            int carrier_family, bool prefer_ipv6, bool mixed_ip_versions) {
        const auto first = carrier_family == AF_INET6 || prefer_ipv6 ? AAAA : A;
        std::vector<DNS_Record_Type> order {first};
        if (mixed_ip_versions)
            order.push_back(first == A ? AAAA : A);
        return order;
    }

    template <class Resolver>
    bool resolve_first_available(
            std::vector<DNS_Record_Type> const& order, Resolver&& resolver) {
        for (auto const type : order) {
            if (resolver(type))
                return true;
        }
        return false;
    }
}

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
