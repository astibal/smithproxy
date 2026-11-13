#ifndef SX_HTTP3_HPP
#define SX_HTTP3_HPP

#include <inspect/engine/http.hpp>
#include <functional>
#include <nlohmann/json.hpp>
#include <inspect/protocol_input.hpp>
#include <proxy/quic/h3capture.hpp>

namespace sx::engine::http::v3 {

struct Http3Stream {
    struct Direction {
        // Incremental DATA locator. Header decoding belongs to the shared
        // connection decoder, including field sections blocked on QPACK.
        std::vector<unsigned char> prefix;
        std::optional<std::uint64_t> stream_type;
        std::optional<std::uint64_t> frame_type;
        std::uint64_t remaining = 0;
        std::string encoding;
        bool final_headers = false;
        std::string metadata_limit;
        std::string published_status;
        std::vector<std::vector<sx::quic::h3_header_field>> headers;
        bool finished = false;
        std::optional<std::uint64_t> reset_error;
    };

    std::array<Direction, 2> directions;
    std::shared_ptr<app_HttpRequest> application = std::make_shared<app_HttpRequest>();
};

struct Http3Connection {
    static constexpr std::size_t maximum_streams = 4096;
    static constexpr std::size_t maximum_history_bytes = 4 * 1024 * 1024;
    static constexpr std::size_t maximum_history_events = 16384;
    static constexpr std::size_t maximum_header_bytes = 4 * 1024 * 1024;

    struct SavedInput {
        ProtocolEndpoint sender;
        ProtocolStream stream;
        ProtocolEvent event;
        std::optional<std::uint64_t> error_code;
        std::vector<unsigned char> bytes;
    };

    std::shared_ptr<sx::quic::h3_capture_decoder> decoder =
        std::make_shared<sx::quic::h3_capture_decoder>();
    std::map<ProtocolStream, Http3Stream> streams;
    std::vector<SavedInput> history;
    std::size_t history_bytes = 0;
    std::size_t header_bytes = 0;
    bool replayable = true;
    bool closed = false;
    std::string published_connection_status;

    // Installed by the multiplexed owner. Output/replay never invokes this
    // input-observation sink; the independent fork keeps the same routing sink.
    std::function<void(std::uint64_t, nlohmann::json)> on_metadata;
};

} // namespace sx::engine::http::v3
#endif
