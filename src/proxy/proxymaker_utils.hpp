#ifndef PROXYMAKER_UTILS_HPP
#define PROXYMAKER_UTILS_HPP

#include <charconv>
#include <memory>
#include <optional>
#include <string_view>

namespace sx::proxymaker {

template<class Host>
bool valid_host_pair(Host const* left, Host const* right) {
    return left != nullptr && right != nullptr &&
           left->com() != nullptr && right->com() != nullptr;
}

template<class Proxy>
bool valid_proxy_endpoints(Proxy const* proxy) {
    return proxy != nullptr &&
           valid_host_pair(proxy->first_left(), proxy->first_right());
}

inline std::optional<unsigned short> parse_source_port(std::string_view text) {
    if(text.empty()) return std::nullopt;
    unsigned int value = 0;
    auto const result = std::from_chars(text.data(), text.data() + text.size(), value);
    if(result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
       value == 0 || value > 65535) {
        return std::nullopt;
    }
    return static_cast<unsigned short>(value);
}

template<class Owner, class Proxy>
bool connect_owned_proxy(Owner* owner, std::unique_ptr<Proxy>&& proxy) {
    if(owner == nullptr || !proxy) return false;
    auto* left = proxy->first_left();
    auto* right = proxy->first_right();
    auto* owner_com = owner->com();
    if(left == nullptr || right == nullptr || owner_com == nullptr) return false;

    const int right_socket = right->connect();
    if(right->com() == nullptr || !right->com()->descriptor_valid(right_socket)) return false;

    owner_com->set_poll_handler(left->socket(), proxy.get());
    owner_com->set_poll_handler(right_socket, proxy.get());
    // The accepted client descriptor changes ownership here. Registering its
    // handler without EPOLLIN leaves a queued ClientHello/request unread.
    owner_com->set_monitor(left->socket());
    // A non-blocking connect completes through EPOLLOUT.  Registering only
    // EPOLLIN leaves a quiet upstream socket permanently in `opening` state.
    owner_com->set_write_monitor(right_socket);
    owner->add_proxy(std::move(proxy));
    return true;
}

} // namespace sx::proxymaker

#endif // PROXYMAKER_UTILS_HPP
