#ifndef PROXYMAKER_UTILS_HPP
#define PROXYMAKER_UTILS_HPP

#include <charconv>
#include <memory>
#include <optional>
#include <string_view>

namespace sx::proxymaker {

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
    if(right_socket <= 0) return false;

    owner_com->set_monitor(right_socket);
    owner_com->set_poll_handler(left->socket(), proxy.get());
    owner_com->set_poll_handler(right_socket, proxy.get());
    owner->add_proxy(std::move(proxy));
    return true;
}

} // namespace sx::proxymaker

#endif // PROXYMAKER_UTILS_HPP
