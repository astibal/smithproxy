#pragma once

#include "proxy/quic/log.hpp"
#include "proxy/quic/error_stats.hpp"
#include <openssl/ssl.h>

namespace sx::quic::logging {

// Observe TLS without replacing certificate policy or the CID message callback.
// No diagnostic exception may escape through the C library callback boundary.
inline void tls_info(SSL const* ssl, int where, int result) noexcept {
    if (!ssl) return;
    try {
        auto const* side = SSL_is_server(ssl) ? "A" : "B";
        if (where & SSL_CB_ALERT) {
            // close_notify is orderly shutdown, not a transport failure.
            if ((result & 0xff) == SSL_AD_CLOSE_NOTIFY) {
                info().dia("ssl=%p %s close_notify %s", static_cast<void const*>(ssl), side,
                           (where & SSL_CB_READ) ? "received" : "sent");
            } else {
                info().war("ssl=%p %s alert %s: %s (%s)", static_cast<void const*>(ssl), side,
                           (where & SSL_CB_READ) ? "received" : "sent",
                           SSL_alert_desc_string_long(result), SSL_alert_type_string_long(result));
            }
        } else if (where & SSL_CB_HANDSHAKE_DONE) {
            info().dia("ssl=%p %s handshake complete reused=%d", static_cast<void const*>(ssl),
                       side, SSL_session_reused(ssl));
        } else if (where & SSL_CB_HANDSHAKE_START) {
            info().deb("ssl=%p %s handshake started", static_cast<void const*>(ssl), side);
        } else if (*info().level() >= DUM) {
            info().dum("ssl=%p %s state='%s' where=0x%x result=%d",
                       static_cast<void const*>(ssl), side, SSL_state_string_long(ssl), where, result);
        }
    } catch (...) {
        ++stats.errors.logging_tls_info_exception;
    }
}

} // namespace sx::quic::logging
