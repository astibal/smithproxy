#include "proxy/quic/h3capture.hpp"

#include <lsqpack.h>
#include <lsxpack_header.h>

#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <utility>

namespace sx::quic {
namespace {

constexpr std::uint64_t h3_frame_data = 0x00;
constexpr std::uint64_t h3_frame_headers = 0x01;
constexpr std::uint64_t h3_stream_qpack_encoder = 0x02;
constexpr std::size_t maximum_field_section = 1024 * 1024;

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
    bool unblocked = false;
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
};

class direction_decoder {
public:
    explicit direction_decoder(socle::side_t side) : side_(side) {
        // The observer accepts a generous local maximum. The peer still
        // controls actual table use through its QPACK encoder instructions.
        lsqpack_dec_init(&decoder_, nullptr, 64 * 1024, 100,
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
        auto& stream = streams_[stream_id];
        auto const unidirectional = (stream_id & 0x02U) != 0;

        if (unidirectional && !stream.stream_type_known) {
            stream.input.insert(stream.input.end(), data, data + size);
            auto const type = read_varint(stream.input.data(), stream.input.size());
            if (!type) return;
            stream.stream_type_known = true;
            stream.stream_type = type->value;
            stream.input.erase(stream.input.begin(),
                               stream.input.begin() + type->size);

            // Only the encoder stream affects QPACK decoding. Control,
            // decoder, push and unknown unidirectional streams remain in the
            // raw SPQ1 capture but need no semantic processing here.
            stream.ignored = stream.stream_type != h3_stream_qpack_encoder;
            if (!stream.ignored && !stream.input.empty()) {
                feed_encoder(stream.input.data(), stream.input.size());
                stream.input.clear();
            }
            return;
        }

        if (unidirectional) {
            if (!stream.ignored && size != 0) feed_encoder(data, size);
            return;
        }

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

private:
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

                if (*stream.frame_type == h3_frame_headers
                    && stream.frame_remaining > maximum_field_section) {
                    // Preserve forwarding and raw capture, but bound semantic
                    // buffering when a peer advertises an absurd frame size.
                    stream.frame_type = h3_frame_data;
                }
            }

            auto const consumed = static_cast<std::size_t>(std::min<std::uint64_t>(
                stream.frame_remaining, stream.input.size()));
            if (*stream.frame_type == h3_frame_headers && consumed != 0) {
                stream.field_section.insert(
                    stream.field_section.end(), stream.input.begin(),
                    stream.input.begin() + consumed);
            }
            stream.input.erase(stream.input.begin(), stream.input.begin() + consumed);
            stream.frame_remaining -= consumed;
            if (stream.frame_remaining != 0) return;

            if (*stream.frame_type == h3_frame_headers) {
                decode_field_section(stream_id, stream.field_section);
            }
            stream.frame_type.reset();
        }
    }

    void decode_field_section(
        std::uint64_t stream_id, std::vector<unsigned char> const& section) {
        auto context = std::make_unique<header_block_context>();
        context->side = side_;
        context->stream_id = stream_id;
        auto const* cursor = section.data();
        std::array<unsigned char, LSQPACK_LONGEST_HEADER_ACK> acknowledgement {};
        std::size_t acknowledgement_size = acknowledgement.size();
        auto const status = lsqpack_dec_header_in(
            &decoder_, context.get(), stream_id, section.size(), &cursor,
            section.size(), acknowledgement.data(), &acknowledgement_size);

        if (status == LQRHS_DONE) {
            publish(std::move(context));
        } else if (status == LQRHS_BLOCKED) {
            context->remaining.assign(cursor, section.data() + section.size());
            pending_.push_back(std::move(context));
        } else if (status == LQRHS_NEED) {
            // The complete H3 frame was supplied, so NEED means the field
            // section is truncated. Release the decoder's context reference.
            lsqpack_dec_unref_stream(&decoder_, context.get());
        }
        // LQRHS_ERROR releases the context internally; raw capture continues.
    }

    void feed_encoder(unsigned char const* data, std::size_t size) {
        if (lsqpack_dec_enc_in(&decoder_, data, size) != 0) return;

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
        if (!context->fields.empty()) {
            records_.push_back({
                context->side, context->stream_id, std::move(context->fields)});
        }
    }

    socle::side_t side_;
    lsqpack_dec decoder_ {};
    std::map<std::uint64_t, stream_state> streams_;
    std::vector<std::unique_ptr<header_block_context>> pending_;
    std::deque<h3_headers_record> records_;
};

} // namespace

class h3_capture_decoder::implementation {
public:
    implementation()
        : client_(socle::side_t::LEFT), server_(socle::side_t::RIGHT) {}

    std::vector<h3_headers_record> ingest(
        socle::side_t side, std::uint64_t stream_id,
        unsigned char const* data, std::size_t size) {
        std::lock_guard lock(lock_);
        auto& decoder = side == socle::side_t::LEFT ? client_ : server_;
        decoder.ingest(stream_id, data, size);

        // Encoder instructions can unblock field sections already observed on
        // another stream, so drain the selected connection direction rather
        // than assuming records belong to the stream currently being fed.
        return decoder.drain_records();
    }

private:
    std::mutex lock_;
    direction_decoder client_;
    direction_decoder server_;
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
