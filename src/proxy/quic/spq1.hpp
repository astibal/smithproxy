#ifndef SMITHPROXY_QUIC_SPQ1_HPP
#define SMITHPROXY_QUIC_SPQ1_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <buffer.hpp>
#include <traflog/basetraflog.hpp>

#include "proxy/quic/h3capture.hpp"

namespace sx::quic::spq1 {

/** Shared identity and packet-number space for one exported QUIC connection. */
struct connection_context {
    connection_context(std::uint64_t id, std::string protocol)
        : session_id(id), alpn(std::move(protocol)),
          h3_decoder(alpn.rfind("h3", 0) == 0
              ? std::make_shared<h3_capture_decoder>() : nullptr) {}

    std::uint64_t session_id = 0;
    std::string alpn;
    std::atomic_uint32_t next_packet_number {1};
    /** Shared across streams because QPACK instructions use dedicated flows. */
    std::shared_ptr<h3_capture_decoder> h3_decoder;
};

/** Metadata which remains constant for one downstream-visible QUIC stream. */
struct stream_context {
    std::shared_ptr<connection_context> connection;
    std::uint64_t stream_id = 0;
};

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
    void finish(socle::side_t side);

private:
    static constexpr std::size_t max_plaintext_per_packet = 1100;

    void emit(socle::side_t side, unsigned char const* data,
              std::size_t size, bool fin);
    void emit(h3_headers_record const& record);
    static std::size_t side_index(socle::side_t side);

    std::unique_ptr<socle::baseTrafficLogger> output_;
    stream_context context_;
    std::uint64_t offsets_[2] {0, 0};
    bool observed_[2] {false, false};
    bool finished_[2] {false, false};
};

} // namespace sx::quic::spq1

#endif // SMITHPROXY_QUIC_SPQ1_HPP
