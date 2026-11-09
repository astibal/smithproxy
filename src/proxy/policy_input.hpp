#pragma once

#include <memory>
#include <string>
#include <vector>
#include <tcpcom.hpp>
#include <hostcx.hpp>

namespace sx::proxy {
// Keep admission endpoints before routing profiles or explicit-proxy handoff
// replace the live contexts. Revalidation must use the same ACL inputs.
struct policy_input_t {
    struct endpoint_t {
        std::string host, port;
        int protocol;
        unsigned ingress;
    };
    std::vector<endpoint_t> left, right;

    static policy_input_t capture(const std::vector<baseHostCX*>& left,
                                  const std::vector<baseHostCX*>& right) {
        policy_input_t input;
        auto copy = [](const auto& contexts, auto& endpoints) {
            for(const auto* cx : contexts) {
                if(cx && cx->com()) endpoints.push_back({cx->host(), cx->port(),
                    cx->com()->policy_l4_proto(), cx->com()->ingress_ifindex()});
                else endpoints.push_back({{}, {}, 0, 0});
            }
        };
        copy(left, input.left);
        copy(right, input.right);
        return input;
    }

    struct view_t {
        std::vector<std::unique_ptr<baseHostCX>> owners;
        std::vector<baseHostCX*> left, right;
    };
    view_t view() const {
        view_t result;
        auto make = [&](const auto& endpoints, auto& contexts) {
            for(const auto& endpoint : endpoints) {
                auto com = std::make_unique<TCPCom>();
                com->l4_proto(endpoint.protocol);
                com->ingress_ifindex(endpoint.ingress);
                auto cx = std::make_unique<baseHostCX>(com.release(), endpoint.host.c_str(), endpoint.port.c_str());
                contexts.push_back(cx.get());
                result.owners.push_back(std::move(cx));
            }
        };
        make(left, result.left);
        make(right, result.right);
        return result;
    }
};
} // namespace sx::proxy
