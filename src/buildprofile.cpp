#include <buildprofile.hpp>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace sx::build_profile {

void initialize_process() noexcept {
    if constexpr (mem_constrained) {
#if defined(__GLIBC__)
        mallopt(M_ARENA_MAX, 1);
        mallopt(M_TRIM_THRESHOLD, 128 * 1024);
#endif
    }
}

} // namespace sx::build_profile
