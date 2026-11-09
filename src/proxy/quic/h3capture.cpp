#include "proxy/quic/h3capture.hpp"

#include <inspect/http_identity.hpp>

#include <lsqpack.h>
#include <lsxpack_header.h>

#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace sx::quic {
namespace {

constexpr std::uint64_t h3_frame_data = 0x00;
constexpr std::uint64_t h3_frame_headers = 0x01;
constexpr std::uint64_t h3_frame_cancel_push = 0x03;
constexpr std::uint64_t h3_frame_settings = 0x04;
constexpr std::uint64_t h3_frame_push_promise = 0x05;
constexpr std::uint64_t h3_frame_goaway = 0x07;
constexpr std::uint64_t h3_frame_max_push_id = 0x0d;
constexpr std::uint64_t h3_stream_control = 0x00;
constexpr std::uint64_t h3_stream_push = 0x01;
constexpr std::uint64_t h3_stream_qpack_encoder = 0x02;
constexpr std::uint64_t h3_stream_qpack_decoder = 0x03;
constexpr std::size_t maximum_field_section = 1024 * 1024;
constexpr std::uint64_t maximum_qpack_dynamic_table_capacity = 1024 * 1024;
constexpr std::size_t maximum_tracked_streams = 4096;
constexpr std::size_t maximum_tracked_push_promises = 64;
constexpr std::size_t maximum_retained_push_promise_bytes =
    8 * maximum_field_section;
constexpr std::size_t maximum_blocked_header_blocks = 8;
constexpr std::size_t maximum_pending_response_records = 8;

constexpr bool is_http2_reserved_frame(std::uint64_t type) {
    return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
}

struct decoded_varint {
    std::uint64_t value = 0;
    std::size_t size = 0;
};

std::optional<decoded_varint> read_varint(
    unsigned char const* data, std::size_t size) {
    if (!data || size == 0) return std::nullopt;
    auto const encoded_size = std::size_t{1} << (data[0] >> 6);
    if (size < encoded_size) return std::nullopt;

    std::uint64_t value = data[0] & 0x3FU;
    for (std::size_t index = 1; index < encoded_size; ++index) {
        value = (value << 8U) | data[index];
    }
    return decoded_varint {value, encoded_size};
}

struct header_block_context {
    socle::side_t side = socle::side_t::LEFT;
    std::uint64_t stream_id = 0;
    std::vector<h3_header_field> fields;
    std::vector<char> storage;
    std::vector<unsigned char> remaining;
    lsxpack_header header {};
    std::size_t field_list_size = 0;
    bool unblocked = false;
    bool trailers = false;
    bool push_promise = false;
    std::optional<std::uint64_t> push_id;
    bool discard = false;
};

void header_unblocked(void* opaque) {
    static_cast<header_block_context*>(opaque)->unblocked = true;
}

lsxpack_header* prepare_header(
    void* opaque, lsxpack_header* existing, std::size_t space) {
    auto* context = static_cast<header_block_context*>(opaque);

    // ls-qpack may first ask for enough room for a header name and then ask
    // us to grow the same buffer once it learns the value length. Keep both
    // the bytes and the decoder-maintained offsets in that second call;
    // reinitialising the header here truncates literal names to their prefix.
    if (space > LSXPACK_MAX_STRLEN) return nullptr;
    context->storage.resize(space);
    if (existing) {
        context->header.buf = context->storage.data();
        context->header.val_len = static_cast<lsxpack_strlen_t>(space);
    } else {
        lsxpack_header_prepare_decode(
            &context->header, context->storage.data(), 0, space);
    }
    return &context->header;
}

int process_header(void* opaque, lsxpack_header* header) {
    auto* context = static_cast<header_block_context*>(opaque);
    auto const name_size = static_cast<std::size_t>(header->name_len);
    auto const value_size = static_cast<std::size_t>(header->val_len);
    if(name_size > maximum_field_section - 32 ||
       value_size > maximum_field_section - 32 - name_size ||
       name_size + value_size + 32 >
           maximum_field_section - context->field_list_size) {
        return 1;
    }
    context->field_list_size += name_size + value_size + 32;
    context->fields.push_back({
        std::string(lsxpack_header_get_name(header), header->name_len),
        std::string(lsxpack_header_get_value(header), header->val_len),
    });
    return 0;
}

lsqpack_dec_hset_if const decoder_callbacks {
    header_unblocked,
    prepare_header,
    process_header,
};

struct stream_state {
    bool stream_type_known = false;
    std::uint64_t stream_type = 0;
    bool ignored = false;
    std::vector<unsigned char> input;
    std::optional<std::uint64_t> frame_type;
    std::uint64_t frame_remaining = 0;
    std::vector<unsigned char> field_section;
    bool headers_frame_seen = false;
    bool final_response_seen = false;
    bool trailers_seen = false;
    bool semantic_invalid = false;
    std::optional<std::uint64_t> content_length;
    std::uint64_t data_bytes = 0;
    bool body_forbidden = false;
    std::string response_status;
    bool response_has_content_length = false;
    bool control_settings_seen = false;
    std::vector<unsigned char> control_settings_input;
    std::vector<unsigned char> control_frame_input;
    std::unordered_set<std::uint64_t> control_setting_ids;
    bool push_id_known = false;
};

struct qpack_limits {
    std::uint64_t maximum_table_capacity = 0;
    std::uint64_t blocked_streams = 0;
};

class direction_decoder {
public:
    direction_decoder(socle::side_t side,
                      bool* advertised_extended_connect,
                      bool const* peer_extended_connect,
                      std::optional<std::uint64_t>* advertised_max_push_id,
                      std::optional<std::uint64_t> const* peer_max_push_id,
                      std::optional<std::uint64_t>* server_goaway_boundary,
                      std::optional<std::uint64_t>* client_goaway_boundary,
                      qpack_limits* advertised_qpack_limits,
                      qpack_limits const* peer_qpack_limits)
        : side_(side),
          advertised_extended_connect_(advertised_extended_connect),
          peer_extended_connect_(peer_extended_connect),
          advertised_max_push_id_(advertised_max_push_id),
          peer_max_push_id_(peer_max_push_id),
          server_goaway_boundary_(server_goaway_boundary),
          client_goaway_boundary_(client_goaway_boundary),
          advertised_qpack_limits_(advertised_qpack_limits),
          peer_qpack_limits_(peer_qpack_limits) {
        // Both settings default to zero until the receiving endpoint
        // advertises otherwise on its control stream.
        lsqpack_dec_init(&decoder_, nullptr, 0, 0,
                         &decoder_callbacks,
                         static_cast<lsqpack_dec_opts>(0));
    }

    ~direction_decoder() {
        for (auto const& context : pending_) {
            lsqpack_dec_unref_stream(&decoder_, context.get());
        }
        lsqpack_dec_cleanup(&decoder_);
    }

    direction_decoder(direction_decoder const&) = delete;
    direction_decoder& operator=(direction_decoder const&) = delete;

    void ingest(std::uint64_t stream_id, unsigned char const* data,
                std::size_t size) {
        if(connection_invalid_) return;
        synchronize_qpack_limits();
        if(connection_invalid_) return;
        auto const unidirectional = (stream_id & 0x02U) != 0;
        if(unidirectional) {
            const std::uint64_t expected_class =
                side_ == socle::side_t::LEFT ? 0x02U : 0x03U;
            if((stream_id & 0x03U) != expected_class) {
                connection_invalid_ = true;
                return;
            }
        }
        // HTTP/3 request streams are client-initiated bidirectional streams.
        // A server-initiated bidi stream is not an HTTP request/response
        // stream, even when its bytes happen to form valid H3 frames.
        if (!unidirectional && (stream_id & 0x03U) != 0) {
            connection_invalid_ = true;
            return;
        }
        if(!unidirectional && side_ == socle::side_t::LEFT &&
           server_goaway_boundary_ && *server_goaway_boundary_ &&
           stream_id >= **server_goaway_boundary_) {
            return;
        }

        auto stream_position = streams_.find(stream_id);
        if (stream_position == streams_.end()) {
            if (streams_.size() >= maximum_tracked_streams) {
                // Ordinary and unknown streams remain under the hard state
                // bound, but they must not starve the three critical stream
                // identities. Their type values are one-byte varints, and
                // HTTP/3 permits only one of each, so admitting them here is
                // bounded while preserving connection-error validation.
                auto const type = unidirectional
                    ? read_varint(data, size) : std::nullopt;
                const bool critical = type &&
                    (type->value == h3_stream_control ||
                     type->value == h3_stream_qpack_encoder ||
                     type->value == h3_stream_qpack_decoder);
                if(!critical) return;
            }
            stream_position = streams_.try_emplace(stream_id).first;
        }
        auto& stream = stream_position->second;

        if (unidirectional && !stream.stream_type_known) {
            stream.input.insert(stream.input.end(), data, data + size);
            auto const type = read_varint(stream.input.data(), stream.input.size());
            if (!type) return;
            stream.stream_type_known = true;
            stream.stream_type = type->value;
            stream.input.erase(stream.input.begin(),
                               stream.input.begin() + type->size);

            // Control and both QPACK streams are critical: HTTP/3 permits
            // exactly one of each per direction.  A client also cannot open a
            // push stream.  Although only the encoder stream feeds this
            // observer's QPACK decoder, accepting another critical stream
            // would let later traffic regain semantics after an endpoint has
            // already rejected the connection.
            auto& critical_stream = stream.stream_type == h3_stream_control
                ? control_stream_
                : stream.stream_type == h3_stream_qpack_encoder
                    ? qpack_encoder_stream_
                    : qpack_decoder_stream_;
            const bool critical = stream.stream_type == h3_stream_control ||
                stream.stream_type == h3_stream_qpack_encoder ||
                stream.stream_type == h3_stream_qpack_decoder;
            const bool client_push = side_ == socle::side_t::LEFT &&
                stream.stream_type == h3_stream_push;
            if(client_push ||
               (critical && critical_stream && *critical_stream != stream_id)) {
                connection_invalid_ = true;
            } else if(critical) {
                critical_stream = stream_id;
            }

            // QPACK encoder and control streams both affect whether later H3
            // semantics are valid. A server push stream needs its leading
            // Push ID validated before its payload can be ignored. Decoder and
            // unknown unidirectional streams remain in raw SPQ1 capture only.
            stream.ignored = stream.stream_type != h3_stream_qpack_encoder &&
                stream.stream_type != h3_stream_control &&
                stream.stream_type != h3_stream_push;
            if(connection_invalid_) stream.ignored = true;
            if(stream.stream_type == h3_stream_control) {
                parse_control_stream(stream);
                return;
            }
            if(stream.stream_type == h3_stream_push) {
                parse_push_stream(stream);
                return;
            }
            if (!stream.ignored && !stream.input.empty()) {
                feed_encoder(stream.input.data(), stream.input.size());
                stream.input.clear();
            }
            return;
        }

        if (unidirectional) {
            if(stream.stream_type == h3_stream_control) {
                stream.input.insert(stream.input.end(), data, data + size);
                parse_control_stream(stream);
            } else if(stream.stream_type == h3_stream_push &&
                      !stream.push_id_known) {
                stream.input.insert(stream.input.end(), data, data + size);
                parse_push_stream(stream);
            } else if (!stream.ignored && size != 0) {
                feed_encoder(data, size);
            }
            return;
        }

        // Once this request stream has a stream-scoped HTTP/3 error or was
        // abandoned by a local capture bound, later bytes cannot regain
        // semantics and must not be reclassified as a connection error using
        // incomplete local state.
        if(stream.semantic_invalid) return;

        stream.stream_type_known = true;
        stream.input.insert(stream.input.end(), data, data + size);
        parse_request_stream(stream_id, stream);
    }

    std::vector<h3_headers_record> drain_records() {
        std::vector<h3_headers_record> output;
        output.reserve(records_.size());
        while (!records_.empty()) {
            output.push_back(std::move(records_.front()));
            records_.pop_front();
        }
        return output;
    }

    [[nodiscard]] bool connection_invalid() const noexcept {
        return connection_invalid_;
    }

    bool set_request_method(std::uint64_t stream_id, std::string method) {
        if(request_methods_.size() >= maximum_tracked_streams &&
           request_methods_.find(stream_id) == request_methods_.end()) {
            return false;
        }
        request_methods_[stream_id] = std::move(method);
        auto stream = streams_.find(stream_id);
        if(stream == streams_.end()) return true;

        auto const& request_method = request_methods_.at(stream_id);
        auto& state = stream->second;
        state.body_forbidden = state.body_forbidden || request_method == "HEAD";
        const bool successful_connect = request_method == "CONNECT" &&
            state.response_status.size() == 3 &&
            state.response_status.front() == '2';
        if((state.body_forbidden && state.data_bytes != 0) ||
           (successful_connect && state.response_has_content_length)) {
            state.semantic_invalid = true;
        }
        return !state.semantic_invalid;
    }

private:
    void synchronize_qpack_limits() {
        if(!peer_qpack_limits_) return;
        auto const capacity = peer_qpack_limits_->maximum_table_capacity;
        auto const blocked = peer_qpack_limits_->blocked_streams;
        if(capacity == decoder_max_capacity_ &&
           blocked == decoder_max_blocked_streams_) return;

        // ls-qpack uses unsigned settings.  A larger, protocol-valid value is
        // outside this observer's representable state, so fail closed instead
        // of decoding with a truncated Required Insert Count modulus.
        if(capacity > maximum_qpack_dynamic_table_capacity ||
           capacity > std::numeric_limits<unsigned>::max() ||
           blocked > std::numeric_limits<unsigned>::max() ||
           !pending_.empty()) {
            connection_invalid_ = true;
            return;
        }

        // Before SETTINGS, capacity is zero: no valid dynamic entry or
        // blocked field section can exist.  Completed static field sections
        // carry no decoder state, so rebuilding here is safe.
        lsqpack_dec_cleanup(&decoder_);
        lsqpack_dec_init(&decoder_, nullptr,
                         static_cast<unsigned>(capacity),
                         static_cast<unsigned>(blocked),
                         &decoder_callbacks,
                         static_cast<lsqpack_dec_opts>(0));
        decoder_max_capacity_ = capacity;
        decoder_max_blocked_streams_ = blocked;
    }

    void parse_push_stream(stream_state& stream) {
        auto const push_id = read_varint(stream.input.data(), stream.input.size());
        if(!push_id) return;
        if(side_ != socle::side_t::RIGHT || !peer_max_push_id_ ||
           !*peer_max_push_id_ || push_id->value > **peer_max_push_id_ ||
           !push_stream_ids_.insert(push_id->value).second) {
            connection_invalid_ = true;
            stream.ignored = true;
            return;
        }
        stream.push_id_known = true;
        stream.ignored = true;
        stream.input.clear();
    }

    void parse_control_settings(stream_state& stream, bool complete) {
        std::size_t consumed = 0;
        while(consumed < stream.control_settings_input.size()) {
            auto const identifier = read_varint(
                stream.control_settings_input.data() + consumed,
                stream.control_settings_input.size() - consumed);
            if(!identifier) break;
            auto const value_offset = consumed + identifier->size;
            auto const value = read_varint(
                stream.control_settings_input.data() + value_offset,
                stream.control_settings_input.size() - value_offset);
            if(!value) break;

            // HTTP/2 setting identifiers are explicitly forbidden in H3.
            // Boolean extension settings likewise have only values 0 and 1.
            const bool forbidden_http2_identifier = identifier->value >= 0x02 &&
                identifier->value <= 0x05;
            const bool invalid_boolean =
                (identifier->value == 0x08 || identifier->value == 0x33) &&
                value->value > 1;
            if(forbidden_http2_identifier || invalid_boolean ||
               !stream.control_setting_ids.insert(identifier->value).second) {
                connection_invalid_ = true;
                return;
            }
            if(identifier->value == 0x08 && advertised_extended_connect_)
                *advertised_extended_connect_ = value->value != 0;
            if(identifier->value == 0x01 && advertised_qpack_limits_)
                advertised_qpack_limits_->maximum_table_capacity = value->value;
            if(identifier->value == 0x07 && advertised_qpack_limits_)
                advertised_qpack_limits_->blocked_streams = value->value;
            consumed = value_offset + value->size;
        }
        stream.control_settings_input.erase(
            stream.control_settings_input.begin(),
            stream.control_settings_input.begin() + consumed);
        if(complete && !stream.control_settings_input.empty()) {
            connection_invalid_ = true;
        }
    }

    void parse_control_stream(stream_state& stream) {
        while(!connection_invalid_) {
            if(!stream.frame_type) {
                auto const type = read_varint(stream.input.data(), stream.input.size());
                if(!type) return;
                auto const length = read_varint(
                    stream.input.data() + type->size,
                    stream.input.size() - type->size);
                if(!length) return;
                stream.frame_type = type->value;
                stream.frame_remaining = length->value;
                stream.input.erase(stream.input.begin(),
                                   stream.input.begin() + type->size + length->size);

                // HTTP/3 reserves the HTTP/2 PRIORITY, PING, WINDOW_UPDATE and
                // CONTINUATION frame types. Unlike unknown extension frames,
                // receiving one is a connection error on every H3 stream.
                if(is_http2_reserved_frame(*stream.frame_type)) {
                    connection_invalid_ = true;
                    return;
                }

                // Every control stream starts with exactly one SETTINGS. DATA,
                // HEADERS and PUSH_PROMISE never belong on it. Once either
                // endpoint rejects the connection, later request bytes must
                // not regain observer semantics.
                if(!stream.control_settings_seen) {
                    if(*stream.frame_type != h3_frame_settings) {
                        connection_invalid_ = true;
                        return;
                    }
                    stream.control_settings_seen = true;
                } else if(*stream.frame_type == h3_frame_settings ||
                          *stream.frame_type == h3_frame_data ||
                          *stream.frame_type == h3_frame_headers ||
                          *stream.frame_type == h3_frame_push_promise) {
                    connection_invalid_ = true;
                    return;
                }
                if((*stream.frame_type == h3_frame_cancel_push ||
                    *stream.frame_type == h3_frame_goaway ||
                    *stream.frame_type == h3_frame_max_push_id) &&
                   stream.frame_remaining > 8) {
                    connection_invalid_ = true;
                    return;
                }
            }

            auto const consumed = static_cast<std::size_t>(std::min<std::uint64_t>(
                stream.frame_remaining, stream.input.size()));
            if(*stream.frame_type == h3_frame_settings && consumed != 0) {
                stream.control_settings_input.insert(
                    stream.control_settings_input.end(), stream.input.begin(),
                    stream.input.begin() + consumed);
            } else if((*stream.frame_type == h3_frame_cancel_push ||
                       *stream.frame_type == h3_frame_goaway ||
                       *stream.frame_type == h3_frame_max_push_id) &&
                      consumed != 0) {
                stream.control_frame_input.insert(
                    stream.control_frame_input.end(), stream.input.begin(),
                    stream.input.begin() + consumed);
            }
            stream.input.erase(stream.input.begin(), stream.input.begin() + consumed);
            stream.frame_remaining -= consumed;
            if(*stream.frame_type == h3_frame_settings) {
                parse_control_settings(stream, stream.frame_remaining == 0);
                if(connection_invalid_) return;
            }
            if(stream.frame_remaining != 0) return;
            if(*stream.frame_type == h3_frame_cancel_push ||
               *stream.frame_type == h3_frame_goaway ||
               *stream.frame_type == h3_frame_max_push_id) {
                auto const value = read_varint(stream.control_frame_input.data(),
                                               stream.control_frame_input.size());
                if(!value || value->size != stream.control_frame_input.size() ||
                   (*stream.frame_type == h3_frame_max_push_id &&
                    side_ == socle::side_t::RIGHT)) {
                    connection_invalid_ = true;
                    return;
                }
                if(*stream.frame_type == h3_frame_goaway) {
                    if((side_ == socle::side_t::RIGHT &&
                        (value->value & 0x03U) != 0) ||
                       (last_goaway_id_ && value->value > *last_goaway_id_)) {
                        connection_invalid_ = true;
                        return;
                    }
                    last_goaway_id_ = value->value;
                    if(side_ == socle::side_t::RIGHT && server_goaway_boundary_)
                        *server_goaway_boundary_ = value->value;
                    if(side_ == socle::side_t::LEFT && client_goaway_boundary_)
                        *client_goaway_boundary_ = value->value;
                } else if(*stream.frame_type == h3_frame_cancel_push) {
                    auto const* maximum = side_ == socle::side_t::LEFT
                        ? advertised_max_push_id_ : peer_max_push_id_;
                    if(!maximum || !*maximum || value->value > **maximum) {
                        connection_invalid_ = true;
                        return;
                    }
                } else if(*stream.frame_type == h3_frame_max_push_id) {
                    if(advertised_max_push_id_ && *advertised_max_push_id_ &&
                       value->value < **advertised_max_push_id_) {
                        connection_invalid_ = true;
                        return;
                    }
                    if(advertised_max_push_id_)
                        *advertised_max_push_id_ = value->value;
                }
                stream.control_frame_input.clear();
            }
            stream.frame_type.reset();
        }
    }

    void parse_request_stream(std::uint64_t stream_id, stream_state& stream) {
        while (true) {
            if (!stream.frame_type) {
                auto const type = read_varint(stream.input.data(), stream.input.size());
                if (!type) return;
                auto const length = read_varint(
                    stream.input.data() + type->size,
                    stream.input.size() - type->size);
                if (!length) return;

                stream.frame_type = type->value;
                stream.frame_remaining = length->value;
                stream.field_section.clear();
                stream.input.erase(
                    stream.input.begin(),
                    stream.input.begin() + type->size + length->size);

                if(is_http2_reserved_frame(*stream.frame_type)) {
                    connection_invalid_ = true;
                    return;
                }

                const bool forbidden_control =
                    *stream.frame_type == h3_frame_cancel_push ||
                    *stream.frame_type == h3_frame_settings ||
                    *stream.frame_type == h3_frame_goaway ||
                    *stream.frame_type == h3_frame_max_push_id;
                const bool client_push_promise = side_ == socle::side_t::LEFT &&
                    *stream.frame_type == h3_frame_push_promise;
                const bool response_data_before_final =
                    side_ == socle::side_t::RIGHT &&
                    *stream.frame_type == h3_frame_data &&
                    !stream.final_response_seen;
                if (forbidden_control || client_push_promise ||
                    response_data_before_final ||
                    (!stream.headers_frame_seen &&
                     *stream.frame_type == h3_frame_data) ||
                    (stream.trailers_seen &&
                     (*stream.frame_type == h3_frame_headers ||
                      *stream.frame_type == h3_frame_data))) {
                    stream.semantic_invalid = true;
                    connection_invalid_ = true;
                    return;
                }

                if(*stream.frame_type == h3_frame_data) {
                    if(stream.frame_remaining >
                       std::numeric_limits<std::uint64_t>::max() -
                           stream.data_bytes) {
                        stream.semantic_invalid = true;
                        return;
                    }
                    stream.data_bytes += stream.frame_remaining;
                    if((stream.body_forbidden && stream.frame_remaining != 0) ||
                       (stream.content_length &&
                        stream.data_bytes > *stream.content_length)) {
                        stream.semantic_invalid = true;
                        return;
                    }
                }

                if (*stream.frame_type == h3_frame_headers
                    && stream.frame_remaining > maximum_field_section) {
                    // Preserve forwarding and raw capture, but bound semantic
                    // buffering when a peer advertises an absurd frame size.
                    // The omitted initial/trailer section also means this
                    // stream's later frame roles can no longer be classified.
                    stream.semantic_invalid = true;
                    stream.frame_type = h3_frame_data;
                }
                if (*stream.frame_type == h3_frame_push_promise
                    && stream.frame_remaining > maximum_field_section) {
                    stream.semantic_invalid = true;
                    stream.frame_type = h3_frame_data;
                }
            }

            auto const consumed = static_cast<std::size_t>(std::min<std::uint64_t>(
                stream.frame_remaining, stream.input.size()));
            if ((*stream.frame_type == h3_frame_headers ||
                 *stream.frame_type == h3_frame_push_promise) && consumed != 0) {
                stream.field_section.insert(
                    stream.field_section.end(), stream.input.begin(),
                    stream.input.begin() + consumed);
            }
            stream.input.erase(stream.input.begin(), stream.input.begin() + consumed);
            stream.frame_remaining -= consumed;
            if (stream.frame_remaining != 0) return;

            if (*stream.frame_type == h3_frame_headers &&
                !stream.semantic_invalid) {
                const bool trailers = side_ == socle::side_t::LEFT
                    ? stream.headers_frame_seen : stream.final_response_seen;
                stream.headers_frame_seen = true;
                stream.trailers_seen = trailers;
                decode_field_section(stream_id, stream.field_section, trailers);
            } else if(*stream.frame_type == h3_frame_push_promise &&
                      !stream.semantic_invalid) {
                auto const push_id = read_varint(stream.field_section.data(),
                                                 stream.field_section.size());
                if(!push_id || !peer_max_push_id_ || !*peer_max_push_id_ ||
                   push_id->value > **peer_max_push_id_ ||
                   push_id->size == stream.field_section.size()) {
                    connection_invalid_ = true;
                    return;
                }
                std::vector<unsigned char> promised_fields(
                    stream.field_section.begin() + push_id->size,
                    stream.field_section.end());
                const bool rejected_by_goaway = client_goaway_boundary_ &&
                    *client_goaway_boundary_ &&
                    push_id->value >= **client_goaway_boundary_;
                decode_field_section(stream_id, promised_fields, false, true,
                                     push_id->value, rejected_by_goaway);
            }
            stream.frame_type.reset();
        }
    }

    void decode_field_section(
        std::uint64_t stream_id, std::vector<unsigned char> const& section,
        bool trailers, bool push_promise = false,
        std::optional<std::uint64_t> push_id = std::nullopt,
        bool discard = false) {
        auto context = std::make_unique<header_block_context>();
        context->side = side_;
        context->stream_id = stream_id;
        context->trailers = trailers;
        context->push_promise = push_promise;
        context->push_id = push_id;
        context->discard = discard;
        auto const* cursor = section.data();
        std::array<unsigned char, LSQPACK_LONGEST_HEADER_ACK> acknowledgement {};
        std::size_t acknowledgement_size = acknowledgement.size();
        auto const status = lsqpack_dec_header_in(
            &decoder_, context.get(), stream_id, section.size(), &cursor,
            section.size(), acknowledgement.data(), &acknowledgement_size);

        if (status == LQRHS_DONE) {
            publish(std::move(context));
        } else if (status == LQRHS_BLOCKED) {
            if(!peer_qpack_limits_ ||
               pending_.size() >= peer_qpack_limits_->blocked_streams) {
                lsqpack_dec_unref_stream(&decoder_, context.get());
                connection_invalid_ = true;
                return;
            }
            // A blocked section retains its compressed bytes, partially
            // decoded fields and decoder state.  The per-frame limit alone
            // would still allow the peer to pin roughly 100 MiB per
            // direction (the decoder's configured blocked-stream limit).
            if(pending_.size() >= maximum_blocked_header_blocks) {
                lsqpack_dec_unref_stream(&decoder_, context.get());
                auto stream = streams_.find(stream_id);
                if(stream != streams_.end())
                    stream->second.semantic_invalid = true;
            } else {
                context->remaining.assign(cursor,
                                          section.data() + section.size());
                pending_.push_back(std::move(context));
            }
        } else if (status == LQRHS_NEED) {
            // The complete H3 frame was supplied, so NEED means the field
            // section is truncated. Release the decoder's context reference.
            lsqpack_dec_unref_stream(&decoder_, context.get());
            connection_invalid_ = true;
        } else if (status == LQRHS_ERROR) {
            connection_invalid_ = true;
        }
        // LQRHS_ERROR releases the context internally; raw capture continues.
    }

    void feed_encoder(unsigned char const* data, std::size_t size) {
        if (lsqpack_dec_enc_in(&decoder_, data, size) != 0) {
            connection_invalid_ = true;
            return;
        }

        for (auto current = pending_.begin(); current != pending_.end();) {
            if (!(*current)->unblocked) {
                ++current;
                continue;
            }

            unsigned char dummy = 0;
            auto const* remaining_begin = (*current)->remaining.empty()
                ? &dummy : (*current)->remaining.data();
            auto const* cursor = remaining_begin;
            auto const remaining_size = (*current)->remaining.size();
            std::array<unsigned char, LSQPACK_LONGEST_HEADER_ACK> acknowledgement {};
            std::size_t acknowledgement_size = acknowledgement.size();
            auto const status = lsqpack_dec_header_read(
                &decoder_, current->get(), &cursor, remaining_size,
                acknowledgement.data(), &acknowledgement_size);
            if (status == LQRHS_DONE) {
                auto decoded = std::move(*current);
                current = pending_.erase(current);
                publish(std::move(decoded));
            } else if (status == LQRHS_ERROR) {
                current = pending_.erase(current);
                connection_invalid_ = true;
                return;
            } else {
                if (remaining_size != 0) {
                    auto const consumed = static_cast<std::size_t>(
                        cursor - remaining_begin);
                    (*current)->remaining.erase(
                        (*current)->remaining.begin(),
                        (*current)->remaining.begin() + consumed);
                }
                ++current;
            }
        }
    }

    void publish(std::unique_ptr<header_block_context> context) {
        if(context->discard) return;
        bool regular_header_seen = false;
        std::unordered_set<std::string> pseudo_headers;
        auto const ascii_equal_ci = [](std::string_view left,
                                       std::string_view right) {
            if(left.size() != right.size()) return false;
            for(std::size_t index = 0; index < left.size(); ++index) {
                unsigned char l = left[index];
                unsigned char r = right[index];
                if(l >= 'A' && l <= 'Z') l += 'a' - 'A';
                if(r >= 'A' && r <= 'Z') r += 'a' - 'A';
                if(l != r) return false;
            }
            return true;
        };
        auto valid_field = [&](h3_header_field const& field) {
            if(field.name.empty()) return false;
            const bool pseudo = field.name.front() == ':';
            const std::size_t token_begin = pseudo ? 1 : 0;
            if(token_begin == field.name.size()) return false;
            for(std::size_t index = token_begin; index < field.name.size(); ++index) {
                const unsigned char ch = field.name[index];
                const bool token = (ch >= 'a' && ch <= 'z') ||
                                   (ch >= '0' && ch <= '9') ||
                                   ch == '!' || ch == '#' || ch == '$' ||
                                   ch == '%' || ch == '&' || ch == '\'' ||
                                   ch == '*' || ch == '+' || ch == '-' ||
                                   ch == '.' || ch == '^' || ch == '_' ||
                                   ch == '`' || ch == '|' || ch == '~';
                if(!token) return false;
            }
            if(pseudo) {
                if(regular_header_seen ||
                   !pseudo_headers.insert(field.name).second) return false;
                const bool request_pseudo = field.name == ":method" ||
                    field.name == ":scheme" || field.name == ":authority" ||
                    field.name == ":path" || field.name == ":protocol";
                const bool response_pseudo = field.name == ":status";
                const bool request_fields = context->side == socle::side_t::LEFT ||
                    context->push_promise;
                if((request_fields && !request_pseudo) ||
                   (!request_fields && !response_pseudo)) {
                    return false;
                }
            } else {
                regular_header_seen = true;
            }
            if(field.name == "connection" || field.name == "proxy-connection" ||
               field.name == "keep-alive" || field.name == "transfer-encoding" ||
               field.name == "upgrade") return false;
            if(field.name == "te" &&
               !ascii_equal_ci(field.value, "trailers")) return false;
            for(unsigned char ch: field.value) {
                // HTTP field-content permits visible bytes, obs-text and
                // internal SP/HTAB. Other C0 controls and DEL do not become
                // valid merely because QPACK can represent them.
                if((ch < 0x20U && ch != '\t') || ch == 0x7fU) return false;
            }
            if(!field.value.empty() &&
               (field.value.front() == ' ' || field.value.front() == '\t' ||
                field.value.back() == ' ' || field.value.back() == '\t')) {
                return false;
            }
            return true;
        };

        const bool valid = std::all_of(
            context->fields.begin(), context->fields.end(), valid_field);
        std::optional<std::uint64_t> content_length;
        bool content_length_valid = true;
        for(auto const& field: context->fields) {
            if(field.name != "content-length") continue;
            if(context->trailers) {
                content_length_valid = false;
                break;
            }
            std::string_view remaining = field.value;
            do {
                const auto comma = remaining.find(',');
                auto item = remaining.substr(0, comma);
                while(!item.empty() && (item.front() == ' ' || item.front() == '\t'))
                    item.remove_prefix(1);
                while(!item.empty() && (item.back() == ' ' || item.back() == '\t'))
                    item.remove_suffix(1);

                std::uint64_t parsed = 0;
                if(item.empty()) content_length_valid = false;
                for(unsigned char ch: item) {
                    if(ch < '0' || ch > '9' ||
                       parsed > (std::numeric_limits<std::uint64_t>::max() -
                                 static_cast<unsigned>(ch - '0')) / 10) {
                        content_length_valid = false;
                        break;
                    }
                    parsed = parsed * 10 + static_cast<unsigned>(ch - '0');
                }
                if(content_length_valid && content_length &&
                   *content_length != parsed) content_length_valid = false;
                if(content_length_valid && !content_length) content_length = parsed;
                if(comma == std::string_view::npos) break;
                remaining.remove_prefix(comma + 1);
            } while(content_length_valid);
            if(!content_length_valid) break;
        }
        auto const pseudo_value = [&](std::string const& name) -> std::string_view {
            auto const item = std::find_if(
                context->fields.begin(), context->fields.end(),
                [&](h3_header_field const& field) { return field.name == name; });
            return item == context->fields.end() ? std::string_view{} : item->value;
        };
        auto const token_value = [](std::string_view value) {
            if(value.empty()) return false;
            return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') ||
                       (ch >= 'A' && ch <= 'Z') ||
                       (ch >= '0' && ch <= '9') ||
                       ch == '!' || ch == '#' || ch == '$' || ch == '%' ||
                       ch == '&' || ch == '\'' || ch == '*' || ch == '+' ||
                       ch == '-' || ch == '.' || ch == '^' || ch == '_' ||
                       ch == '`' || ch == '|' || ch == '~';
            });
        };
        auto const scheme_value = [](std::string_view value) {
            if(value.empty() || !((value.front() >= 'a' && value.front() <= 'z') ||
                                  (value.front() >= 'A' && value.front() <= 'Z')))
                return false;
            return std::all_of(value.begin() + 1, value.end(), [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') ||
                       (ch >= 'A' && ch <= 'Z') ||
                       (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' ||
                       ch == '.';
            });
        };
        bool complete = valid && content_length_valid && !context->fields.empty();
        if(complete && context->trailers) {
            complete = pseudo_headers.empty();
        } else if(complete && (context->side == socle::side_t::LEFT ||
                               context->push_promise)) {
            auto const method = pseudo_value(":method");
            auto const scheme = pseudo_value(":scheme");
            auto const authority = pseudo_value(":authority");
            auto const host = pseudo_value("host");
            auto const path = pseudo_value(":path");
            auto const protocol = pseudo_value(":protocol");
            const auto host_count = std::count_if(
                context->fields.begin(), context->fields.end(),
                [](h3_header_field const& field) { return field.name == "host"; });
            const bool conflicting_authority = !authority.empty() &&
                !host.empty() && !ascii_equal_ci(authority, host);
            const auto effective_authority = authority.empty() ? host : authority;
            const bool missing_required_authority =
                sx::inspect::http_detail::scheme_requires_authority(scheme) &&
                effective_authority.empty();
            const bool empty_explicit_authority =
                pseudo_headers.count(":authority") != 0 && authority.empty() &&
                sx::inspect::http_detail::scheme_requires_authority(scheme);
            // Unlike an ordinary request, a pushed request cannot use Host
            // as a fallback: RFC 9114 requires the server to send
            // :authority explicitly in PUSH_PROMISE.
            const bool missing_push_authority =
                context->push_promise && authority.empty();
            if(!token_value(method) || (!protocol.empty() && !token_value(protocol)) ||
               (!scheme.empty() && !scheme_value(scheme)) || host_count > 1 ||
               conflicting_authority || missing_required_authority ||
               empty_explicit_authority || missing_push_authority ||
               (!effective_authority.empty() &&
                !sx::inspect::http_detail::is_unambiguous_authority(
                    effective_authority))) {
                complete = false;
            } else if(method == "CONNECT") {
                complete = !authority.empty() &&
                    (protocol.empty()
                        ? scheme.empty() && path.empty()
                        : peer_extended_connect_ &&
                          *peer_extended_connect_ &&
                          !scheme.empty() &&
                          sx::inspect::http_detail::is_valid_request_path(
                              method, path));
            } else {
                complete = protocol.empty() && !scheme.empty() &&
                    sx::inspect::http_detail::is_valid_request_path(method, path);
            }
        } else if(complete) {
            auto const status = pseudo_value(":status");
            complete = status.size() == 3 &&
                status.front() >= '1' && status.front() <= '5' &&
                std::all_of(status.begin(), status.end(), [](unsigned char ch) {
                    return ch >= '0' && ch <= '9';
                }) && status != "101";
            if(complete && content_length &&
               (status.front() == '1' || status == "204" ||
                (status == "205" && *content_length != 0))) {
                complete = false;
            }
        }
        if(complete && context->push_promise && context->push_id) {
            const auto existing = promised_push_fields_.find(*context->push_id);
            if(existing == promised_push_fields_.end()) {
                std::size_t retained_size = 0;
                for(auto const& field: context->fields)
                    retained_size += field.name.size() + field.value.size() + 32;
                if(promised_push_fields_.size() >= maximum_tracked_push_promises ||
                   retained_size > maximum_retained_push_promise_bytes -
                                       retained_push_promise_bytes_) {
                    connection_invalid_ = true;
                    return;
                }
                retained_push_promise_bytes_ += retained_size;
            }
            auto const [stored, inserted] = promised_push_fields_.emplace(
                *context->push_id, context->fields);
            if(!inserted) {
                auto const equal = stored->second.size() == context->fields.size() &&
                    std::equal(stored->second.begin(), stored->second.end(),
                               context->fields.begin(),
                               [](h3_header_field const& left,
                                  h3_header_field const& right) {
                                   return left.name == right.name &&
                                          left.value == right.value;
                               });
                if(!equal) {
                    connection_invalid_ = true;
                    return;
                }
            }
        }
        if (complete && !context->push_promise) {
            auto stream = streams_.find(context->stream_id);
            if(stream != streams_.end() && context->trailers &&
               stream->second.content_length &&
               stream->second.data_bytes != *stream->second.content_length) {
                complete = false;
            }
            if(stream != streams_.end() && !context->trailers) {
                bool body_forbidden = false;
                if(context->side == socle::side_t::RIGHT) {
                    const auto status = pseudo_value(":status");
                    body_forbidden = status == "204" || status == "205" ||
                        status == "304";
                    stream->second.response_status = status;
                    stream->second.response_has_content_length =
                        content_length.has_value();
                    if(auto method = request_methods_.find(context->stream_id);
                       method != request_methods_.end()) {
                        body_forbidden = body_forbidden ||
                            method->second == "HEAD";
                        if(method->second == "CONNECT" &&
                           status.front() == '2' && content_length) {
                            complete = false;
                        }
                    }
                }
                stream->second.body_forbidden = body_forbidden;
                stream->second.content_length = body_forbidden
                    ? std::optional<std::uint64_t>{} : content_length;
                if((body_forbidden && stream->second.data_bytes != 0) ||
                   (stream->second.content_length &&
                    stream->second.data_bytes > *stream->second.content_length)) {
                    stream->second.semantic_invalid = true;
                    return;
                }
            }
            if(context->side == socle::side_t::RIGHT && !context->trailers) {
                auto const status = pseudo_value(":status");
                if(!status.empty() && status.front() != '1') {
                    if(stream != streams_.end())
                        stream->second.final_response_seen = true;
                }
            }
            if(complete) {
                records_.push_back({
                    context->side, context->stream_id, std::move(context->fields)});
            }
        }
        if(!complete) {
            // Invalid field semantics are an H3_MESSAGE_ERROR for this
            // request stream.  QPACK decoding above must still advance the
            // connection-wide compression state, but later bytes on the
            // rejected stream cannot regain HTTP semantics.
            auto stream = streams_.find(context->stream_id);
            if(stream != streams_.end())
                stream->second.semantic_invalid = true;
        }
    }

    socle::side_t side_;
    bool* advertised_extended_connect_ = nullptr;
    bool const* peer_extended_connect_ = nullptr;
    std::optional<std::uint64_t>* advertised_max_push_id_ = nullptr;
    std::optional<std::uint64_t> const* peer_max_push_id_ = nullptr;
    std::optional<std::uint64_t>* server_goaway_boundary_ = nullptr;
    std::optional<std::uint64_t>* client_goaway_boundary_ = nullptr;
    qpack_limits* advertised_qpack_limits_ = nullptr;
    qpack_limits const* peer_qpack_limits_ = nullptr;
    std::uint64_t decoder_max_capacity_ = 0;
    std::uint64_t decoder_max_blocked_streams_ = 0;
    lsqpack_dec decoder_ {};
    std::map<std::uint64_t, stream_state> streams_;
    std::optional<std::uint64_t> control_stream_;
    std::optional<std::uint64_t> qpack_encoder_stream_;
    std::optional<std::uint64_t> qpack_decoder_stream_;
    std::optional<std::uint64_t> last_goaway_id_;
    std::unordered_map<std::uint64_t, std::vector<h3_header_field>>
        promised_push_fields_;
    std::size_t retained_push_promise_bytes_ = 0;
    std::unordered_set<std::uint64_t> push_stream_ids_;
    std::vector<std::unique_ptr<header_block_context>> pending_;
    std::deque<h3_headers_record> records_;
    std::unordered_map<std::uint64_t, std::string> request_methods_;
    bool connection_invalid_ = false;
};

} // namespace

class h3_capture_decoder::implementation {
public:
    implementation()
        : client_(socle::side_t::LEFT, nullptr,
                  &server_extended_connect_enabled_,
                  &client_max_push_id_, nullptr,
                  &server_goaway_boundary_,
                  &client_goaway_boundary_,
                  &client_qpack_limits_, &server_qpack_limits_),
          server_(socle::side_t::RIGHT,
                  &server_extended_connect_enabled_, nullptr,
                  nullptr, &client_max_push_id_,
                  &server_goaway_boundary_,
                  &client_goaway_boundary_,
                  &server_qpack_limits_, &client_qpack_limits_) {}

    std::vector<h3_headers_record> ingest(
        socle::side_t side, std::uint64_t stream_id,
        unsigned char const* data, std::size_t size) {
        std::lock_guard lock(lock_);
        if(connection_invalid_) return {};
        auto& decoder = side == socle::side_t::LEFT ? client_ : server_;
        decoder.ingest(stream_id, data, size);
        if(decoder.connection_invalid()) {
            connection_invalid_ = true;
            return {};
        }

        // Encoder instructions can unblock field sections already observed on
        // another stream, so drain the selected connection direction rather
        // than assuming records belong to the stream currently being fed.
        auto records = decoder.drain_records();
        if(side == socle::side_t::LEFT) {
            for(auto const& record: records) {
                request_streams_.insert(record.stream_id);
                auto const method = std::find_if(
                    record.fields.begin(), record.fields.end(),
                    [](h3_header_field const& field) {
                        return field.name == ":method";
                    });
                if(method != record.fields.end() &&
                   !server_.set_request_method(record.stream_id, method->value)) {
                    pending_responses_.erase(std::remove_if(
                        pending_responses_.begin(), pending_responses_.end(),
                        [&](h3_headers_record const& pending) {
                            return pending.stream_id == record.stream_id;
                        }), pending_responses_.end());
                }
            }

            // The two QUIC directions may be delivered by independent
            // callbacks. A valid response observed first is not unsolicited
            // once its request record arrives; release it with the request
            // rather than losing response inspection semantics to timing.
            for(auto current = pending_responses_.begin();
                current != pending_responses_.end();) {
                if(request_streams_.find(current->stream_id) ==
                   request_streams_.end()) {
                    ++current;
                    continue;
                }
                records.push_back(std::move(*current));
                current = pending_responses_.erase(current);
            }
        } else {
            auto current = records.begin();
            while(current != records.end()) {
                if(request_streams_.find(current->stream_id) !=
                   request_streams_.end()) {
                    ++current;
                    continue;
                }
                if(pending_responses_.size() < maximum_pending_response_records)
                    pending_responses_.push_back(std::move(*current));
                current = records.erase(current);
            }
        }
        return records;
    }

private:
    std::mutex lock_;
    bool server_extended_connect_enabled_ = false;
    std::optional<std::uint64_t> client_max_push_id_;
    std::optional<std::uint64_t> server_goaway_boundary_;
    std::optional<std::uint64_t> client_goaway_boundary_;
    qpack_limits client_qpack_limits_;
    qpack_limits server_qpack_limits_;
    direction_decoder client_;
    direction_decoder server_;
    std::unordered_set<std::uint64_t> request_streams_;
    std::deque<h3_headers_record> pending_responses_;
    bool connection_invalid_ = false;
};

h3_capture_decoder::h3_capture_decoder()
    : implementation_(std::make_unique<implementation>()) {}

h3_capture_decoder::~h3_capture_decoder() = default;

std::vector<h3_headers_record> h3_capture_decoder::ingest(
    socle::side_t side, std::uint64_t stream_id,
    unsigned char const* data, std::size_t size) {
    if (!data || size == 0) return {};
    return implementation_->ingest(side, stream_id, data, size);
}

} // namespace sx::quic
