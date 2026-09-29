#ifndef SMITHPROXY_QUIC_H3CAPTURE_HPP
#define SMITHPROXY_QUIC_H3CAPTURE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <vars.hpp>

namespace sx::quic {

/** One name/value pair recovered from an HTTP/3 QPACK field section. */
struct h3_header_field {
    std::string name;
    std::string value;
};

/** Semantic HTTP/3 record emitted independently of raw QUIC stream chunks. */
struct h3_headers_record {
    socle::side_t side = socle::side_t::LEFT;
    std::uint64_t stream_id = 0;
    std::vector<h3_header_field> fields;
};

/**
 * Incrementally observes HTTP/3 streams and owns connection-wide QPACK state.
 *
 * HTTP/3 request streams contain framed field sections, while QPACK encoder
 * instructions arrive on separate unidirectional streams. Consequently the
 * decoder must be shared by every stream in one QUIC connection. One QPACK
 * direction is maintained for client-originated fields and one for server-
 * originated fields.
 */
class h3_capture_decoder final {
public:
    h3_capture_decoder();
    ~h3_capture_decoder();

    h3_capture_decoder(h3_capture_decoder const&) = delete;
    h3_capture_decoder& operator=(h3_capture_decoder const&) = delete;

    /** Feed one ordered plaintext fragment and return newly decoded headers. */
    std::vector<h3_headers_record> ingest(
        socle::side_t side, std::uint64_t stream_id,
        unsigned char const* data, std::size_t size);

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

} // namespace sx::quic

#endif // SMITHPROXY_QUIC_H3CAPTURE_HPP
