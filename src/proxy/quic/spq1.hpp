#ifndef SMITHPROXY_QUIC_SPQ1_HPP
#define SMITHPROXY_QUIC_SPQ1_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <buffer.hpp>
#include <traflog/basetraflog.hpp>

#include "proxy/trafficcapture.hpp"
#include "proxy/quic/h3capture.hpp"

namespace sx::quic::spq1 {

/** Shared identity and packet-number space for one exported QUIC connection. */
struct connection_context {
    connection_context(std::uint64_t id, std::string protocol,
                       std::shared_ptr<sx::session_traffic_log> native_log = {})
        : session_id(id), alpn(std::move(protocol)),
          h3_decoder(alpn.rfind("h3", 0) == 0
              ? std::make_shared<h3_capture_decoder>() : nullptr),
          h3_observer_decoder(alpn.rfind("h3", 0) == 0
              ? std::make_shared<h3_capture_decoder>() : nullptr),
          native_log(std::move(native_log)) {}

    std::uint64_t session_id = 0;
    std::string alpn;
    std::atomic_uint32_t next_packet_number {1};
    /** Shared across streams because QPACK instructions use dedicated flows. */
    std::shared_ptr<h3_capture_decoder> h3_decoder;
    /** Independent decoder used even when packet capture is disabled. */
    std::shared_ptr<h3_capture_decoder> h3_observer_decoder;
    /** Encrypted session packets and secrets routed into the selected logger. */
    std::shared_ptr<sx::session_traffic_log> native_log;

    /** Remember decoded Content-Encoding across H3 DATA messages. */
    void content_encoding(socle::side_t side, std::uint64_t stream_id,
                          std::string value);
    [[nodiscard]] std::string content_encoding(
        socle::side_t side, std::uint64_t stream_id) const;

private:
    static std::uint64_t stream_side_key(
        socle::side_t side, std::uint64_t stream_id);
    mutable std::mutex content_encoding_lock;
    std::unordered_map<std::uint64_t, std::string> content_encodings;
};

/** Metadata which remains constant for one downstream-visible QUIC stream. */
struct stream_context {
    std::shared_ptr<connection_context> connection;
    std::uint64_t stream_id = 0;
};

/** Convert a decoded initial request field section to canonical flow metadata. */
std::unordered_map<std::string, std::string> h3_flow_observations(
    h3_headers_record const& record);

/** Serialize one plaintext STREAM frame inside the private SPQ1 QUIC envelope. */
std::vector<unsigned char> encode_stream_packet(
    stream_context const& context, std::uint64_t offset,
    unsigned char const* data, std::size_t size, bool fin);

/** Serialize decoded HTTP/3 headers as an SPQ1 private extension frame. */
std::vector<unsigned char> encode_h3_headers_packet(
    connection_context& context, h3_headers_record const& record);

/**
 * Decorate an ordinary traffic logger with the SPQ1 plaintext representation.
 *
 * The wrapped PcapLog still owns PCAPNG writing and the optional GRE hook. This
 * class only supplies self-contained synthetic QUIC/STREAM UDP payloads and
 * tracks per-direction stream offsets. Large buffers are split so GRE export
 * does not depend on IP fragmentation.
 */
class stream_log final : public socle::baseTrafficLogger {
public:
    stream_log(std::unique_ptr<socle::baseTrafficLogger> output,
               stream_context context);
    ~stream_log() override;

    void write(socle::side_t side, buffer const& data) override;
    void write(socle::side_t side, std::string const& comment) override;
    /** Forward native wire packets without applying the SPQ1 transformation. */
    void write_packet(socle::side_t side, buffer const& data) override;
    /** Forward session secrets to the capture implementation unchanged. */
    void write_secret(socle::traffic_secret_format format,
                      buffer const& data) override;
    void finish(socle::side_t side);

private:
    struct shared_output_tag {};
    stream_log(std::shared_ptr<socle::baseTrafficLogger> output,
               stream_context context, shared_output_tag);
    friend class stream_log_adapter;

    static constexpr std::size_t max_plaintext_per_packet = 1100;

    void emit(socle::side_t side, unsigned char const* data,
              std::size_t size, bool fin);
    void emit(h3_headers_record const& record);
    static std::size_t side_index(socle::side_t side);

    std::shared_ptr<socle::baseTrafficLogger> output_;
    stream_context context_;
    std::uint64_t offsets_[2] {0, 0};
    bool observed_[2] {false, false};
    bool finished_[2] {false, false};
};

/** Bind one logical stream to packet-capture output without leaking SPQ1 up-stack. */
class stream_log_adapter final : public sx::traffic_log_adapter {
public:
    explicit stream_log_adapter(stream_context context)
        : context_(std::move(context)) {}

    std::unique_ptr<socle::baseTrafficLogger> wrap(
        std::unique_ptr<socle::baseTrafficLogger> output) override;
    std::optional<content_metadata> inspect_content(
        socle::side_t side, buffer const& data) override;
    void on_flow_observation(observation_hook hook) override {
        observation_hook_ = std::move(hook);
    }

private:
    struct frame_state {
        // A frame type and length are both QUIC varints, hence at most 16
        // header bytes even when a content message ends halfway through them.
        std::vector<unsigned char> header;
        std::optional<std::uint64_t> type;
        std::uint64_t remaining = 0;
    };

    std::vector<std::pair<std::int64_t, std::int64_t>> data_ranges(
        socle::side_t side, buffer const& data);
    static std::size_t side_index(socle::side_t side);

    stream_context context_;
    observation_hook observation_hook_;
    frame_state frames_[2];
};

} // namespace sx::quic::spq1

#endif // SMITHPROXY_QUIC_SPQ1_HPP
