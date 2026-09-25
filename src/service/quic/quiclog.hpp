#ifndef SMITHPROXY_QUICLOG_HPP
#define SMITHPROXY_QUICLOG_HPP

#include <log/logan.hpp>

namespace sx::quic {

/** Shared lightweight logger controlled by `debug set com.quic <level>`. */
inline logan_lite& log() {
    static logan_lite instance {"com.quic"};
    return instance;
}

} // namespace sx::quic

#endif // SMITHPROXY_QUICLOG_HPP
