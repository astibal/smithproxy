#ifndef SX_PAYLOAD_ANALYSIS_HPP
#define SX_PAYLOAD_ANALYSIS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sx::engine {

// Callback-local results depending ONLY on bytes, never on protocol history.
// Own the original bytes: a webhook may modify its buffer in place. Pointer
// identity or size alone must never authorize reuse of an earlier result.
class PayloadAnalysis {
public:
    // No snapshot means an uncached publication request. This also lets callers
    // request protocol-only work without allocating or copying payload bytes.
    PayloadAnalysis() = default;
    explicit PayloadAnalysis(std::string_view original) : original_(original) {}

    static PayloadAnalysis protocol_only() {
        PayloadAnalysis result;
        result.publish_identity_ = false;
        return result;
    }

    bool matches(std::string_view bytes) const {
        return original_ && *original_ == bytes;
    }

    std::optional<std::uint64_t> publication_fingerprint(std::string_view bytes) {
        // Absence is intentional, not a cache miss. Do not hash or compare
        // bytes when this observation has no webhook consumer.
        if (!publish_identity_) return std::nullopt;

        return fingerprint(bytes);
    }

    static std::uint64_t calculate_fingerprint(std::string_view bytes) {
        std::uint64_t value = 14695981039346656037ULL;

        for (unsigned char byte : bytes) {
            value ^= byte;
            value *= 1099511628211ULL;
        }

        return value;
    }

    std::uint64_t fingerprint(std::string_view bytes) {
        if (!matches(bytes)) return calculate_fingerprint(bytes);

        if (!fingerprint_) fingerprint_ = calculate_fingerprint(*original_);

        return *fingerprint_;
    }

private:
    std::optional<std::string> original_;
    std::optional<std::uint64_t> fingerprint_;
    bool publish_identity_ = true;
};

} // namespace sx::engine
#endif
