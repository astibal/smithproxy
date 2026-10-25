#include <sslcom.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace {

/** Exposes only the protected ClientHello parser to the fuzz harness. */
class client_hello_parser final : public SSLCom {
public:
    void assign(std::uint8_t const* data, std::size_t size) {
        sslcom_peer_hello_buffer.assign(
            const_cast<std::uint8_t*>(data), size, size, false);
    }

    int parse() { return parse_peer_hello(); }
};

[[noreturn]] void invariant_failed() {
    __builtin_trap();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (!data || size == 0) return 0;
    size = std::min<std::size_t>(size, 64 * 1024);

    client_hello_parser parser;
    parser.assign(data, size);
    try {
        parser.parse();
    } catch (socle::ex::SSL_clienthello_malformed const&) {
        // Malformed length fields are a normal parser result.
    }

    if (parser.get_sni().size() > size || parser.get_peer_alpn().size() > size) {
        invariant_failed();
    }
    return 0;
}
