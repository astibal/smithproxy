#pragma once

#include <log/logan.hpp>

namespace sx::quic {

// Independent topics keep packet traces separate from admission and lifecycle.
// Register them at service construction so debug commands work before traffic.
inline logan_lite& log() {
    static logan_lite value {"com.quic"};
    return value;
}

namespace logging {

// TLS state changes and alerts on both A and B.
inline logan_lite& info() {
    static logan_lite value {"com.quic.cb.info"};
    return value;
}

// Protocol selection and agreement between the two legs.
inline logan_lite& alpn() {
    static logan_lite value {"com.quic.cb.alpn"};
    return value;
}

// CRYPTO/frame metadata only; never payloads or traffic secrets.
inline logan_lite& message() {
    static logan_lite value {"com.quic.cb.msg"};
    return value;
}

// Session admission, activation and draining.
inline logan_lite& session() {
    static logan_lite value {"com.quic.cb.session"};
    return value;
}

// Certificate policy decisions, including explicit exceptions.
inline logan_lite& verify() {
    static logan_lite value {"com.quic.cb.verify"};
    return value;
}

// Certificate jobs and the identity installed on A.
inline logan_lite& mitm() {
    static logan_lite value {"com.quic.mitm"};
    return value;
}

// Asynchronous revocation checks and their final result.
inline logan_lite& ocsp() {
    static logan_lite value {"com.quic.ocsp"};
    return value;
}

// Logical stream creation and byte/ACK progress.
inline logan_lite& stream() {
    static logan_lite value {"com.quic.stream"};
    return value;
}

// Datagrams, timers and transport failures.
inline logan_lite& transport() {
    static logan_lite value {"com.quic.transport"};
    return value;
}

inline void initialize() {
    (void)log();
    (void)info();
    (void)alpn();
    (void)message();
    (void)session();
    (void)verify();
    (void)mitm();
    (void)ocsp();
    (void)stream();
    (void)transport();
}

} // namespace logging
} // namespace sx::quic
