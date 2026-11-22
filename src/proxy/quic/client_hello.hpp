#pragma once

#include <cstdint>
#include <memory>
#include <utility>
#include <buffer.hpp>
#include <openssl/ssl.h>
#include "proxy/quic/error_stats.hpp"

namespace sx::quic {

// OpenSSL's parsed extension getters omit unknown extensions. Retain the
// original incoming handshake instead, including its four-byte TLS header.
// SSL owns this short-lived evidence even when admission fails before take().
class ClientHelloCapture {
public:
    static void observe(int writing, int, int type, const void* data,
                        size_t size, SSL* ssl, void*) noexcept {
        const bool client_hello = !writing && type == SSL3_RT_HANDSHAKE
            && data && size >= 4 && size <= 256 * 1024
            && static_cast<const uint8_t*>(data)[0] == SSL3_MT_CLIENT_HELLO;
        if (!ssl || !client_hello) return;

        try {
            const auto slot = index();
            if (slot < 0) {
                ++stats.errors.client_hello_capture_failures;
                return;
            }
            if (SSL_get_ex_data(ssl, slot)) return;
            const auto* bytes = static_cast<const uint8_t*>(data);
            const size_t declared = (size_t{bytes[1]} << 16)
                | (size_t{bytes[2]} << 8) | bytes[3];
            if (declared != size - 4) return;
            auto copy = std::make_unique<buffer>(bytes, size);
            const bool stored = SSL_set_ex_data(ssl, slot, copy.get()) == 1;
            if (stored) copy.release();
            else ++stats.errors.client_hello_capture_failures;
        } catch (...) {
            // Count without allocating or logging: observability must never
            // terminate a valid TLS handshake, even under memory pressure.
            ++stats.errors.client_hello_capture_failures;
        }
    }

    static buffer take(SSL* ssl) {
        if (!ssl) return buffer{};
        const auto slot = index();
        if (slot < 0) {
            ++stats.errors.client_hello_capture_failures;
            return buffer{};
        }
        auto* value = static_cast<buffer*>(SSL_get_ex_data(ssl, slot));
        if (!value) return buffer{};
        const bool detached = SSL_set_ex_data(ssl, slot, nullptr) == 1;
        if (!detached) {
            ++stats.errors.client_hello_capture_failures;
            return buffer{}; // SSL still owns the evidence.
        }
        std::unique_ptr<buffer> owner(value);
        return std::move(*owner);
    }

private:
    static int index() {
        static const int slot = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
            [](void*, void* value, CRYPTO_EX_DATA*, int, long, void*) {
                delete static_cast<buffer*>(value);
            });
        return slot;
    }
};

} // namespace sx::quic
