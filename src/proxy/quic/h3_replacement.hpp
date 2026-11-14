#ifndef SX_QUIC_H3_REPLACEMENT_HPP
#define SX_QUIC_H3_REPLACEMENT_HPP

#include <proxy/multiflow/mfproxy.hpp>
#include <proxy/quic/h3capture.hpp>
#include <buffer.hpp>

namespace sx::quic {

struct h3_replacement_reply {
    std::string body;
    unsigned status = 403;
    bool head_only = false;
    bool reconnect = false;
};

// This endpoint has no upstream reference. Rejected certificate sessions can
// only consume client requests and produce local responses.
class h3_replacement final : public multiflow::flow_proxy {
public:
    using handler = std::function<h3_replacement_reply(h3_headers_record const&)>;

    h3_replacement(multiflow::connection_ptr client, handler respond,
                   multiflow::proxy_limits limits);

    void shutdown() override;

    std::size_t pump_once(std::size_t chunk_size = 16 * 1024) override;
    std::size_t pair_count() const override { return streams_.size(); }
    std::size_t queued_bytes() const override;
    std::size_t limit_rejections() const override { return rejected_; }
    multiflow::flow_summary summary() const override;

private:
    struct stream {
        multiflow::flow_handle handle;

        std::uint64_t wire_id = 0;
        buffer output;
        std::optional<h3_headers_record> request;
        std::size_t offset = 0;
        bool responded = false;
        bool finished = false;
        bool peer_finished = false;
    };

    // False means a critical stream closed the connection; stop this pump pass.
    bool pump_stream_once(stream& value, std::size_t chunk_size, std::size_t& progress);
    std::size_t flush_output(multiflow::flow_handle handle, buffer const& data,
                             std::size_t& offset, std::size_t chunk_size);
    void respond(h3_headers_record const& record);
    void goaway(std::uint64_t next_id);

    multiflow::connection_ptr client_;
    handler respond_;
    multiflow::proxy_limits limits_;

    std::map<multiflow::flow_id, stream> streams_;

    h3_capture_decoder decoder_;

    multiflow::flow_handle control_;

    buffer control_output_;
    std::size_t control_offset_ = 0;

    std::size_t rejected_ = 0;
    std::uint64_t next_request_id_ = 0;
    std::uint64_t received_ = 0;
    std::uint64_t sent_ = 0;
    bool closing_ = false;
};

} // namespace sx::quic
#endif
