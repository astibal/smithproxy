#ifndef SX_HTTP3_SETTINGS_HPP
#define SX_HTTP3_SETTINGS_HPP

#include <inspect/engine/http3_constants.hpp>
#include <buffer.hpp>
#include <cstdint>
#include <stdexcept>

namespace sx::engine::http::v3 {

// One outgoing unidirectional stream. QUIC is terminated on both proxy legs,
// and neither leg forwards DATAGRAM frames. Do not advertise that capability
// just because the original endpoint supports it (RFC 9297, section 2.1.1).
//
// Process bytes incrementally without buffering a peer-sized SETTINGS frame.
// Preserve every varint's width, so frame lengths and stream offsets stay valid,
// even when an integer arrives one byte at a time. QPACK/unknown streams bypass
// this parser after their type; only SETTINGS values on control streams change.
class SettingsNormalizer {
public:
    void apply(buffer& output) {
        auto* bytes = static_cast<unsigned char*>(output.data());

        for (std::size_t i = 0; i < output.size(); ++i) {
            if (phase_ == Phase::Passthrough) return;

            if (phase_ == Phase::SkipPayload) {
                if (--remaining_ == 0) phase_ = Phase::FrameType;
                continue;
            }

            const auto original = bytes[i];
            const bool first_byte = integer_left_ == 0;
            const bool setting_payload = phase_ == Phase::SettingId || phase_ == Phase::SettingValue;
            const bool disable_datagram = phase_ == Phase::SettingValue &&
                (setting_id_ == setting::h3_datagram || setting_id_ == setting::h3_datagram_draft03);

            if (first_byte) {
                integer_left_ = 1U << (original >> 6);
                integer_ = original & 0x3fU;
            } else {
                integer_ = (integer_ << 8) | original;
            }
            --integer_left_;

            if (disable_datagram) {
                // Example: a two-byte true (40 01) becomes two-byte zero
                // (40 00), not 00. The high two width bits must survive.
                bytes[i] = first_byte ? original & 0xc0U : 0;
            }

            if (setting_payload) {
                --remaining_;

                // A value may not consume bytes from the following frame.
                if (remaining_ == 0 && (integer_left_ != 0 || phase_ == Phase::SettingId)) {
                    throw std::runtime_error("Truncated HTTP/3 SETTINGS pair");
                }
            }

            if (integer_left_ != 0) continue;

            switch (phase_) {
            case Phase::StreamType:
                phase_ = integer_ == control_stream ? Phase::FrameType : Phase::Passthrough;
                break;
            case Phase::FrameType:
                frame_type_ = integer_;
                phase_ = Phase::FrameLength;
                break;
            case Phase::FrameLength:
                remaining_ = integer_;
                phase_ = Phase::FrameType;

                if (remaining_ != 0) {
                    phase_ = frame_type_ == settings_frame ? Phase::SettingId : Phase::SkipPayload;
                }
                break;
            case Phase::SettingId:
                setting_id_ = integer_;
                phase_ = Phase::SettingValue;
                break;
            case Phase::SettingValue:
                // Do not turn malformed boolean settings into valid output.
                if (disable_datagram && integer_ > 1) {
                    throw std::runtime_error("Invalid HTTP/3 DATAGRAM setting");
                }
                phase_ = remaining_ == 0 ? Phase::FrameType : Phase::SettingId;
                break;
            default:
                break;
            }
        }
    }

private:
    enum class Phase { StreamType, FrameType, FrameLength, SettingId, SettingValue,
                       SkipPayload, Passthrough };
    static constexpr std::uint64_t control_stream = 0;
    static constexpr std::uint64_t settings_frame = 4;

    Phase phase_ = Phase::StreamType;
    unsigned integer_left_ = 0;
    std::uint64_t integer_ = 0;
    std::uint64_t frame_type_ = 0;
    std::uint64_t remaining_ = 0;
    std::uint64_t setting_id_ = 0;
};

} // namespace sx::engine::http::v3
#endif
