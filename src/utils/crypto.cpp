#include "crypto.hpp"
#include <ossl_util.hpp>

namespace sx::crypto {

std::string hex(unsigned char const* data, std::size_t size) {
    return socle::ossl::hex_encode(data, size);
}

std::optional<std::string> sha256(std::string_view input) {
    return socle::ossl::sha256(input);
}

std::optional<std::string> random_hex(std::size_t bytes) {
    return socle::ossl::random_hex(bytes);
}

} // namespace sx::crypto
