#pragma once
#include <atomic>
#include <cstdint>

namespace sx::quic {

// Fixed storage survives session teardown and log rotation. Failure accounting
// must not allocate or log while handling an exception. These are site counts,
// not unique failures: propagation can increment several different sites.
struct error_counter {
    void operator++() noexcept { value.fetch_add(1, std::memory_order_relaxed); }
    std::uint64_t load() const noexcept { return value.load(std::memory_order_relaxed); }
private:
    std::atomic_uint64_t value {0};
};

struct error_statistics {
#define QUIC_ERROR_SITE(name) error_counter name;
#include "proxy/quic/error_sites.inc"
#undef QUIC_ERROR_SITE

    // Management reads an approximate concurrent snapshot; counters never reset.
    template<class Visitor> void visit(Visitor&& visitor) const {
#define QUIC_ERROR_SITE(name) visitor(#name, name.load());
#include "proxy/quic/error_sites.inc"
#undef QUIC_ERROR_SITE
    }
};
struct statistics { error_statistics errors; };
inline statistics stats;

} // namespace sx::quic
