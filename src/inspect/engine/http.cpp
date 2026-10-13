#include <sslcom.hpp>

#include <inspect/engine/http.hpp>
#include <inspect/fp/ja4.hpp>
#include <inspect/http_identity.hpp>
#include <proxy/mitmhost.hpp>

#ifdef USE_HPACK
#include <ext/hpack/hpack.hpp>
#endif

#include <inspect/dnsinspector.hpp>
#include <inspect/kb/kb.hpp>

#include <charconv>

namespace sx::engine::http {

    namespace {
        std::optional<L7PayloadRange> intersect_payload(
                                        std::size_t payload_start,
                                        std::size_t payload_end,
                                        std::size_t current_offset,
                                        std::size_t block_size) {
            if(current_offset > block_size || payload_start > payload_end ||
               payload_end > block_size) return std::nullopt;

            const auto start = std::max(payload_start, current_offset);
            const auto end = std::min(payload_end, block_size);
            if(start >= end) return std::nullopt;
            return L7PayloadRange{
                static_cast<std::int64_t>(start - current_offset),
                static_cast<std::int64_t>(end - current_offset)
            };
        }

        bool ascii_equal_ci(std::string_view left, std::string_view right) {
            if(left.size() != right.size()) return false;
            return std::equal(left.begin(), left.end(), right.begin(),
                [](unsigned char l, unsigned char r) {
                    return std::tolower(l) == std::tolower(r);
                });
        }

        bool ascii_contains_ci(std::string_view value, std::string_view needle) {
            if(needle.size() > value.size()) return false;
            for(std::size_t offset = 0; offset + needle.size() <= value.size(); ++offset) {
                if(ascii_equal_ci(value.substr(offset, needle.size()), needle)) return true;
            }
            return false;
        }

        std::optional<std::string_view> header_value(std::string_view headers,
                                                      std::string_view name) {
            auto line_start = headers.find('\n');
            if(line_start == std::string_view::npos) return std::nullopt;
            ++line_start;
            while(line_start < headers.size()) {
                auto line_end = headers.find('\n', line_start);
                if(line_end == std::string_view::npos) line_end = headers.size();
                auto line = headers.substr(line_start, line_end - line_start);
                if(!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if(line.empty()) break;
                const auto colon = line.find(':');
                if(colon != std::string_view::npos &&
                   ascii_equal_ci(line.substr(0, colon), name)) {
                    auto value = line.substr(colon + 1);
                    while(!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                        value.remove_prefix(1);
                    while(!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                        value.remove_suffix(1);
                    return value;
                }
                line_start = line_end + (line_end < headers.size());
            }
            return std::nullopt;
        }

        std::vector<std::string_view> header_values(std::string_view headers,
                                                     std::string_view name) {
            std::vector<std::string_view> values;
            auto line_start = headers.find('\n');
            if(line_start == std::string_view::npos) return values;
            ++line_start;
            while(line_start < headers.size()) {
                auto line_end = headers.find('\n', line_start);
                if(line_end == std::string_view::npos) line_end = headers.size();
                auto line = headers.substr(line_start, line_end - line_start);
                if(!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if(line.empty()) break;
                const auto colon = line.find(':');
                if(colon != std::string_view::npos &&
                   ascii_equal_ci(line.substr(0, colon), name)) {
                    auto value = line.substr(colon + 1);
                    while(!value.empty() &&
                          (value.front() == ' ' || value.front() == '\t'))
                        value.remove_prefix(1);
                    while(!value.empty() &&
                          (value.back() == ' ' || value.back() == '\t'))
                        value.remove_suffix(1);
                    values.push_back(value);
                }
                line_start = line_end + (line_end < headers.size());
            }
            return values;
        }
    }

    L7PayloadHints v1::Http1Direction::observe(
            std::string_view data, bool response_side,
            std::deque<std::string>* pending_methods) {
        L7PayloadHints ranges;
        last_encodings_.clear();
        auto add_body = [&](std::size_t start, std::size_t end) {
            if(start == end) return;
            if(!ranges.empty() && ranges.back().second == static_cast<std::int64_t>(start) &&
               last_encodings_.back() == message_.encoding) {
                ranges.back().second = static_cast<std::int64_t>(end);
            } else {
                ranges.emplace_back(static_cast<std::int64_t>(start),
                                    static_cast<std::int64_t>(end));
                last_encodings_.push_back(message_.encoding);
            }
        };
        auto finish_line = [&]() {
            if(message_.pending.empty() || message_.pending.back() != '\n') return false;
            while(!message_.pending.empty() &&
                  (message_.pending.back() == '\r' || message_.pending.back() == '\n'))
                message_.pending.pop_back();
            return true;
        };

        std::size_t cursor = 0;
        while(cursor < data.size()) {
            switch(message_.phase) {
                case v1::Http1Message::phase_t::headers: {
                    message_.pending.push_back(data[cursor++]);
                    if(message_.pending.size() > 65536) {
                        message_.pending.clear();
                        message_.phase = v1::Http1Message::phase_t::opaque;
                        break;
                    }
                    const bool complete = message_.pending.size() >= 4 &&
                        message_.pending.compare(message_.pending.size() - 4, 4, "\r\n\r\n") == 0;
                    const bool complete_lf = message_.pending.size() >= 2 &&
                        message_.pending.compare(message_.pending.size() - 2, 2, "\n\n") == 0;
                    if(!complete && !complete_lf) break;

                    const auto headers = std::string_view(message_.pending);
                    message_.encoding.clear();
                    if(auto value = header_value(headers, "content-encoding"))
                        message_.encoding.assign(value->data(), value->size());
                    const auto transfer_values = header_values(headers, "transfer-encoding");
                    const auto length_values = header_values(headers, "content-length");
                    const auto transfer = transfer_values.empty()
                        ? std::optional<std::string_view>{}
                        : std::optional<std::string_view>{transfer_values.front()};
                    const auto length = length_values.empty()
                        ? std::optional<std::string_view>{}
                        : std::optional<std::string_view>{length_values.front()};
                    const auto connection = header_value(headers, "connection");
                    const auto upgrade = header_value(headers, "upgrade");

                    bool body_forbidden = false;
                    bool final_response = false;
                    bool successful_connect = false;
                    std::string request_method;
                    if(response_side && headers.substr(0, 5) == "HTTP/") {
                        const auto first_space = headers.find(' ');
                        if(first_space != std::string_view::npos && first_space + 4 <= headers.size()) {
                            unsigned status = 0;
                            auto parsed = std::from_chars(headers.data() + first_space + 1,
                                                          headers.data() + first_space + 4,
                                                          status);
                            if(parsed.ec == std::errc{}) {
                                const bool informational = status >= 100 && status < 200;
                                final_response = !informational || status == 101;
                                body_forbidden = informational || status == 204 ||
                                                 status == 205 || status == 304;
                                if(final_response && pending_methods &&
                                   !pending_methods->empty()) {
                                    body_forbidden = body_forbidden ||
                                        ascii_equal_ci(pending_methods->front(), "HEAD");
                                    successful_connect = status >= 200 && status < 300 &&
                                        ascii_equal_ci(pending_methods->front(), "CONNECT");
                                }
                            }
                        }
                    } else if(!response_side && pending_methods) {
                        const auto method_end = headers.find(' ');
                        if(method_end != std::string_view::npos && method_end != 0)
                            request_method.assign(headers.substr(0, method_end));
                    }
                    message_.pending.clear();
                    if(transfer_values.size() > 1 || length_values.size() > 1 ||
                       (transfer && !ascii_equal_ci(*transfer, "chunked"))) {
                        message_.phase = v1::Http1Message::phase_t::opaque;
                    } else if(successful_connect ||
                              (connection && ascii_contains_ci(*connection, "upgrade")) || upgrade) {
                        message_.phase = v1::Http1Message::phase_t::opaque;
                    } else if(body_forbidden) {
                        message_.phase = v1::Http1Message::phase_t::headers;
                    } else if(transfer && ascii_contains_ci(*transfer, "chunked")) {
                        message_.phase = v1::Http1Message::phase_t::chunk_size;
                    } else if(length) {
                        std::uint64_t parsed_length = 0;
                        auto parsed = std::from_chars(length->data(),
                                                      length->data() + length->size(),
                                                      parsed_length);
                        if(parsed.ec != std::errc{} ||
                           parsed.ptr != length->data() + length->size()) {
                            message_.phase = v1::Http1Message::phase_t::opaque;
                        } else if(parsed_length == 0) {
                            message_.phase = v1::Http1Message::phase_t::headers;
                        } else {
                            message_.remaining = parsed_length;
                            message_.phase = v1::Http1Message::phase_t::fixed_body;
                        }
                    } else {
                        message_.phase = response_side ? v1::Http1Message::phase_t::until_close
                                                       : v1::Http1Message::phase_t::headers;
                    }
                    if(!response_side && pending_methods && !request_method.empty() &&
                       message_.phase != v1::Http1Message::phase_t::opaque)
                        pending_methods->push_back(std::move(request_method));
                    if(final_response && pending_methods && !pending_methods->empty())
                        pending_methods->pop_front();
                    break;
                }
                case v1::Http1Message::phase_t::fixed_body: {
                    const auto count = static_cast<std::size_t>(
                        std::min<std::uint64_t>(message_.remaining, data.size() - cursor));
                    add_body(cursor, cursor + count);
                    cursor += count;
                    message_.remaining -= count;
                    if(message_.remaining == 0) message_.phase = v1::Http1Message::phase_t::headers;
                    break;
                }
                case v1::Http1Message::phase_t::chunk_size: {
                    message_.pending.push_back(data[cursor++]);
                    if(message_.pending.size() > 128) {
                        message_.pending.clear();
                        message_.phase = v1::Http1Message::phase_t::opaque;
                        break;
                    }
                    if(!finish_line()) break;
                    auto size_text = std::string_view(message_.pending);
                    if(auto extension = size_text.find(';'); extension != std::string_view::npos)
                        size_text = size_text.substr(0, extension);
                    while(!size_text.empty() && (size_text.front() == ' ' || size_text.front() == '\t'))
                        size_text.remove_prefix(1);
                    while(!size_text.empty() && (size_text.back() == ' ' || size_text.back() == '\t'))
                        size_text.remove_suffix(1);
                    std::uint64_t chunk_size = 0;
                    auto parsed = std::from_chars(size_text.data(),
                                                  size_text.data() + size_text.size(),
                                                  chunk_size, 16);
                    message_.pending.clear();
                    if(size_text.empty() || parsed.ec != std::errc{} ||
                       parsed.ptr != size_text.data() + size_text.size()) {
                        message_.phase = v1::Http1Message::phase_t::opaque;
                    } else if(chunk_size == 0) {
                        message_.phase = v1::Http1Message::phase_t::trailers;
                    } else {
                        message_.remaining = chunk_size;
                        message_.phase = v1::Http1Message::phase_t::chunk_data;
                    }
                    break;
                }
                case v1::Http1Message::phase_t::chunk_data: {
                    const auto count = static_cast<std::size_t>(
                        std::min<std::uint64_t>(message_.remaining, data.size() - cursor));
                    add_body(cursor, cursor + count);
                    cursor += count;
                    message_.remaining -= count;
                    if(message_.remaining == 0)
                        message_.phase = v1::Http1Message::phase_t::chunk_delimiter;
                    break;
                }
                case v1::Http1Message::phase_t::chunk_delimiter:
                    message_.pending.push_back(data[cursor++]);
                    if(message_.pending.back() == '\n') {
                        message_.pending.clear();
                        message_.phase = v1::Http1Message::phase_t::chunk_size;
                    } else if(message_.pending.size() > 1 || message_.pending.back() != '\r') {
                        message_.pending.clear();
                        message_.phase = v1::Http1Message::phase_t::opaque;
                    }
                    break;
                case v1::Http1Message::phase_t::trailers:
                    message_.pending.push_back(data[cursor++]);
                    if(message_.pending.size() > 65536) {
                        message_.pending.clear();
                        message_.phase = v1::Http1Message::phase_t::opaque;
                    } else if(finish_line()) {
                        const bool final_line = message_.pending.empty();
                        message_.pending.clear();
                        if(final_line) message_.phase = v1::Http1Message::phase_t::headers;
                    }
                    break;
                case v1::Http1Message::phase_t::until_close:
                    add_body(cursor, data.size());
                    cursor = data.size();
                    break;
                case v1::Http1Message::phase_t::opaque:
                    cursor = data.size();
                    break;
            }
        }
        // A framing error anywhere in this input invalidates ranges already
        // collected from the same block. Publishing a prefix would present
        // attacker-controlled malformed framing as trusted L7 content.
        if(message_.phase == v1::Http1Message::phase_t::opaque) {
            last_encodings_.assign(1, "");
            return L7PayloadHints{{-1, -1}};
        }
        if(!ranges.empty()) return ranges;
        last_encodings_.assign(1, "");
        return L7PayloadHints{{0, 0}};
    }

    void v1::observe_content(EngineCtx& ctx, std::size_t direction,
                             std::string_view data, std::uint64_t read_bytes,
                             bool response_side) {
        auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
        if(!app || app->version != app_HttpRequest::HTTP_VER::HTTP_1) return;

        auto* connection = std::any_cast<Http1Connection>(&ctx.state_data);
        if(!connection) {
            ctx.state_data = std::make_any<Http1Connection>();
            connection = std::any_cast<Http1Connection>(&ctx.state_data);
        }

        auto ranges = connection->observe(direction, data, response_side);
        app->observe_l7_payload(data, read_bytes, std::move(ranges),
                                connection->encodings(direction));
    }

    L7PayloadHints http2_payload_hint(std::string_view block,
                                      std::size_t current_offset) {
        const L7PayloadHints unknown{{-1, -1}};
        const L7PayloadHints none{{0, 0}};
        if(current_offset > block.size()) return unknown;

        std::size_t offset = 0;
        if(block.size() >= v2::txt::magic_sz &&
           block.substr(0, v2::txt::magic_sz) == v2::txt::magic) {
            offset = v2::txt::magic_sz;
        }
        L7PayloadHints ranges;

        while(offset < block.size()) {
            if(block.size() - offset < 9) return unknown;
            const auto* bytes = reinterpret_cast<const unsigned char*>(block.data() + offset);
            const std::size_t length = (static_cast<std::size_t>(bytes[0]) << 16U) |
                                       (static_cast<std::size_t>(bytes[1]) << 8U) |
                                       static_cast<std::size_t>(bytes[2]);
            const auto type = bytes[3];
            const auto flags = bytes[4];
            if(length > block.size() - offset - 9) return unknown;

            if(type == 0 && length != 0) {
                auto payload_start = offset + 9;
                auto payload_end = payload_start + length;
                if((flags & 0x08U) != 0) {
                    const auto padding = static_cast<std::size_t>(bytes[9]);
                    if(padding + 1 > length) return unknown;
                    ++payload_start;
                    payload_end -= padding;
                }
                if(auto range = intersect_payload(payload_start, payload_end,
                                                  current_offset, block.size()))
                    ranges.push_back(*range);
            }
            offset += 9 + length;
        }
        return ranges.empty() ? none : ranges;
    }

    namespace v1 {

        namespace {
            bool header_name_equal(std::string_view left,
                                   std::string_view right) {
                if(left.size() != right.size()) return false;
                for(std::size_t i = 0; i < left.size(); ++i) {
                    const auto l = static_cast<unsigned char>(left[i]);
                    const auto r = static_cast<unsigned char>(right[i]);
                    if(std::tolower(l) != std::tolower(r)) return false;
                }
                return true;
            }

            enum class header_value_state { absent, valid, invalid };

            struct header_value_result {
                header_value_state state = header_value_state::absent;
                std::string_view value;
            };

            header_value_result exact_header_field(
                    std::string_view data, std::string_view wanted_name) {
                header_value_result result;
                std::size_t offset = 0;
                while(offset < data.size()) {
                    auto end = data.find('\n', offset);
                    if(end == std::string_view::npos) end = data.size();
                    auto line = data.substr(offset, end - offset);
                    if(!line.empty() && line.back() == '\r') line.remove_suffix(1);
                    offset = end < data.size() ? end + 1 : data.size();
                    if(line.empty()) break;

                    const auto colon = line.find(':');
                    if(colon == std::string_view::npos ||
                       !header_name_equal(line.substr(0, colon), wanted_name)) {
                        continue;
                    }
                    auto value = line.substr(colon + 1);
                    while(!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                        value.remove_prefix(1);
                    while(!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                        value.remove_suffix(1);
                    if(value.empty() || value.find_first_of(" \t\r\n") != std::string_view::npos ||
                       result.state != header_value_state::absent) {
                        return {header_value_state::invalid, {}};
                    }
                    result = {header_value_state::valid, value};
                }
                return result;
            }

            std::optional<std::string_view> exact_header_value(
                    std::string_view data, std::string_view wanted_name) {
                auto const result = exact_header_field(data, wanted_name);
                if(result.state != header_value_state::valid) return std::nullopt;
                return result.value;
            }

            header_value_result host_header_field(std::string_view data) {
                auto result = exact_header_field(data, "host");
                if(result.state == header_value_state::valid &&
                   !sx::inspect::http_detail::is_unambiguous_authority(result.value)) {
                    result = {header_value_state::invalid, {}};
                }
                return result;
            }

            struct request_line {
                std::string_view method;
                std::string_view target;
                std::string_view version;
            };

            enum class absolute_target_state { not_absolute, valid, invalid };

            struct absolute_target_result {
                absolute_target_state state = absolute_target_state::not_absolute;
                std::string_view authority;
                std::string_view path_and_query;
            };

            bool ascii_starts_with_ci(std::string_view value,
                                      std::string_view prefix) noexcept {
                if(value.size() < prefix.size()) return false;
                for(std::size_t i = 0; i < prefix.size(); ++i) {
                    auto const left = static_cast<unsigned char>(value[i]);
                    auto const right = static_cast<unsigned char>(prefix[i]);
                    if(std::tolower(left) != std::tolower(right)) return false;
                }
                return true;
            }

            absolute_target_result parse_absolute_target(std::string_view target) {
                std::size_t scheme_size = 0;
                if(ascii_starts_with_ci(target, "http://")) scheme_size = 7;
                else if(ascii_starts_with_ci(target, "https://")) scheme_size = 8;
                else return {};

                auto const authority_end = target.find_first_of("/?#", scheme_size);
                auto const authority = target.substr(
                    scheme_size, authority_end == std::string_view::npos
                        ? std::string_view::npos : authority_end - scheme_size);
                if(!sx::inspect::http_detail::is_unambiguous_authority(authority) ||
                   target.find('#', scheme_size) != std::string_view::npos) {
                    return {absolute_target_state::invalid, {}, {}};
                }

                auto path = authority_end == std::string_view::npos
                    ? std::string_view{} : target.substr(authority_end);
                return {absolute_target_state::valid, authority, path};
            }

            bool complete_header_section(std::string_view data) {
                return data.find("\r\n\r\n") != std::string_view::npos ||
                       data.find("\n\n") != std::string_view::npos;
            }

            bool valid_header_lines(std::string_view data) {
                auto offset = data.find('\n');
                if(offset == std::string_view::npos) return false;
                ++offset;
                while(offset < data.size()) {
                    auto end = data.find('\n', offset);
                    if(end == std::string_view::npos) return false;
                    auto line = data.substr(offset, end - offset);
                    if(!line.empty() && line.back() == '\r') line.remove_suffix(1);
                    offset = end + 1;
                    if(line.empty()) return true;
                    if(line.front() == ' ' || line.front() == '\t') return false;

                    auto const colon = line.find(':');
                    if(colon == std::string_view::npos || colon == 0) return false;
                    auto const token_char = [](unsigned char ch) {
                        return std::isalnum(ch) || ch == '!' || ch == '#' || ch == '$' ||
                               ch == '%' || ch == '&' || ch == '\'' || ch == '*' ||
                               ch == '+' || ch == '-' || ch == '.' || ch == '^' ||
                               ch == '_' || ch == '`' || ch == '|' || ch == '~';
                    };
                    if(!std::all_of(line.begin(), line.begin() + colon, token_char))
                        return false;
                    if(std::any_of(line.begin() + colon + 1, line.end(),
                                   [](unsigned char ch) {
                                       return (ch < 0x20U && ch != '\t') || ch == 0x7fU;
                                   })) {
                        return false;
                    }
                }
                return false;
            }

            std::optional<request_line> parse_request_line(std::string_view data) {
                auto end = data.find('\n');
                auto line = data.substr(0, end);
                if(!line.empty() && line.back() == '\r') line.remove_suffix(1);
                const auto first_space = line.find(' ');
                if(first_space == std::string_view::npos || first_space == 0)
                    return std::nullopt;
                auto target_begin = line.find_first_not_of(' ', first_space);
                if(target_begin == std::string_view::npos) return std::nullopt;
                const auto second_space = line.find(' ', target_begin);
                if(second_space == std::string_view::npos || second_space == target_begin)
                    return std::nullopt;
                auto version_begin = line.find_first_not_of(' ', second_space);
                if(version_begin == std::string_view::npos) return std::nullopt;
                auto version = line.substr(version_begin);
                if(version != "HTTP/1.0" && version != "HTTP/1.1")
                    return std::nullopt;

                auto method = line.substr(0, first_space);
                constexpr std::array<std::string_view, 9> methods {
                    "GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT",
                    "OPTIONS", "TRACE", "PATCH"
                };
                if(std::find(methods.begin(), methods.end(), method) == methods.end())
                    return std::nullopt;
                auto target = line.substr(target_begin, second_space - target_begin);
                if(!std::all_of(target.begin(), target.end(), [](unsigned char ch) {
                       return ch > 0x20U && ch < 0x7fU;
                   })) {
                    return std::nullopt;
                }
                return request_line{method, target, version};
            }
        }

        bool find_referrer (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            if (auto value = exact_header_value(data, "referer")) {

                    if (not ctx.application_data) {
                        ctx.application_data = std::make_unique<app_HttpRequest>();
                    }

                    auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                    if (app_request != nullptr) {
                        app_request->http_data.referer.assign(value->data(), value->size());
                        _deb("Referer: %s", ESC(app_request->http_data.referer));
                    }

                    return true;
            }

            return false;
        }

        bool find_host (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            if (not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }
            auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
            if(not app_request) {
                return false;
            }

            auto const field = host_header_field(data);
            if(field.state == header_value_state::valid) {
                app_request->http_data.host.assign(field.value.data(), field.value.size());
                _dia("Host: %s", app_request->http_data.host.c_str());


                // NOTE: should be some config variable
                bool check_inspect_dns_cache = true;
                if (check_inspect_dns_cache) {

                    std::string dns_resp;
                    std::string prefix = "A:";
                    if(ctx.origin and ctx.origin->com()) {
                        auto proto = ctx.origin->com()->l3_proto();
                        prefix = (proto == AF_INET6 ? "AAAA:" : "A:");
                    }

                    // get lock and cache pointers
                    {
                        auto dc_ = std::scoped_lock(DNS::get().dns_lock());
                        auto dns_resp_ptr = DNS::get().dns_cache().get(prefix + app_request->http_data.host);
                        if(dns_resp_ptr) dns_resp = dns_resp_ptr->question_str_0();
                    }

                    if (not dns_resp.empty()) {
                        _deb("HTTP inspection: Host header matches DNS: %s", ESC(dns_resp));
                    } else {
                        _war("HTTP inspection: 'Host' header value '%s' DOESN'T match DNS!",
                             app_request->http_data.host.c_str());
                    }
                }

                return true;
            }
            else {
                if(ctx.origin and ctx.origin->peer())
                    app_request->http_data.host = ctx.origin->peer()->host();
            }

            return false;
        }

        bool find_method (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;
            if (auto parsed = parse_request_line(data)) {
                    if (not ctx.application_data) {
                        ctx.application_data = std::make_unique<app_HttpRequest>();
                    }
                    auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                    if(not app_request) {
                        _err("find_method: incorrect appdata object type");
                        return false;
                    }

                    app_request->http_data.method.assign(
                        parsed->method.data(), parsed->method.size());
                    _dia("method: %s", ESC(app_request->http_data.method));

                    app_request->version = app_HttpRequest::HTTP_VER::HTTP_1;
                    const auto query = parsed->target.find('?');
                    const auto uri = parsed->target.substr(0, query);
                    app_request->http_data.uri.assign(uri.data(), uri.size());
                    _dia("uri: %s", ESC(app_request->http_data.uri));
                    app_request->http_data.params.clear();
                    if(query != std::string_view::npos) {
                        const auto params = parsed->target.substr(query + 1);
                        app_request->http_data.params.assign(params.data(), params.size());
                        _dia("params: %s", ESC(app_request->http_data.params));
                    }

                return true;
            }
            return false;
        }

        std::vector<std::string_view> split_string_view(std::string_view str, std::string_view delimiter,
                                                        bool first_only,
                                                        bool stop_on_empty) {
            std::vector<std::string_view> result;
            size_t start = 0;

            while (start < str.size()) {
                size_t end = str.find(delimiter, start);

                if (end == std::string_view::npos) {
                    result.emplace_back(str.substr(start));
                    break;
                }

                const auto part = str.substr(start, end - start);
                if(stop_on_empty and part.empty()) {
                    break;
                }
                result.emplace_back(part);
                start = end + delimiter.size();

                if(first_only and result.size() == 2) break;
            }

            return result;
        }

        void parse_request(EngineCtx &ctx, buffer const* buffer_data) {
            auto const& log = log::http1;

            auto data = buffer_data->string_view();

            // Flow appends consecutive stream chunks to the same buffer and
            // start() rescans it when it grows. Do not publish a request before
            // all headers arrived.
            if(!complete_header_section(data)) return;
            if(!valid_header_lines(data)) return;

            // A missing Host can still be meaningful for HTTP/1.0 and is
            // handled by the existing peer fallback. An explicitly present
            // but ambiguous Host must not become that fallback identity.
            auto const host_field = host_header_field(data);
            if(host_field.state == header_value_state::invalid) return;

            auto const request = parse_request_line(data);
            if(!request || (request->version == "HTTP/1.1" &&
                            host_field.state == header_value_state::absent))
                return;
            auto const absolute_target = parse_absolute_target(request->target);
            if(absolute_target.state == absolute_target_state::invalid) return;
            bool const connect_authority = request->method == "CONNECT";
            if(connect_authority &&
               !sx::inspect::http_detail::is_unambiguous_authority(request->target)) {
                return;
            }

            bool const have_method = find_method(ctx, data);
            if(have_method) {
                auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());

                auto engine_http1_set_proto = [&ctx, &app_request] {

                    if (app_request != nullptr and ctx.origin and ctx.origin->com()) {
                        // detect protocol (plain vs ssl)
                        auto const* proto_com = dynamic_cast<SSLCom *>(ctx.origin->com());
                        if (proto_com != nullptr) {
                            app_request->http_data.proto = "https://";
                            app_request->is_ssl = true;
                        } else {
                            app_request->http_data.proto = "http://";
                        }

                        _inf("http request: %s", ESC(app_request->str()));
                    } else {
                        _err("http request: app_request failed");
                    }
                };


                bool const have_host = find_host(ctx, data);
                bool const have_referer = find_referrer(ctx, data);

                // For absolute-form requests the request-target authority,
                // not Host, is what an HTTP recipient routes. Keep inspector
                // identity and displayed path on that same view.
                if(app_request && absolute_target.state == absolute_target_state::valid) {
                    app_request->http_data.host.assign(
                        absolute_target.authority.data(), absolute_target.authority.size());
                    auto path = absolute_target.path_and_query;
                    if(path.empty()) path = "/";
                    if(path.front() == '?') {
                        app_request->http_data.uri = "/";
                        app_request->http_data.params.assign(path.data() + 1, path.size() - 1);
                    } else {
                        auto const query = path.find('?');
                        auto const path_size = query == std::string_view::npos
                            ? path.size() : query;
                        app_request->http_data.uri.assign(path.data(), path_size);
                        app_request->http_data.params.clear();
                        if(query != std::string_view::npos) {
                            app_request->http_data.params.assign(
                                path.data() + query + 1, path.size() - query - 1);
                        }
                    }
                } else if(app_request && connect_authority) {
                    app_request->http_data.host.assign(
                        request->target.data(), request->target.size());
                    app_request->http_data.uri.clear();
                    app_request->http_data.params.clear();
                }

                engine_http1_set_proto();

                if(ctx.origin) ctx.origin->replacement_type(MitmHostCX::REPLACETYPE_HTTP);

                if(not have_host) _not("http1: 'Host:' not found");
                if(not have_referer) _deb("http1: 'Referer:' not found");

                if(app_request) {

                    if(ctx.options.http.ja4h) {
                        sx::ja4::HTTP h;
                        h.version = "11";
                        h.from_buffer(data);

                        app_request->http_data.ja4h = h.ja4h();
                    }

                    app_request->mark_populated();
                }
            }
            else {
                // probably not HTTP
            }
        }

        void start (EngineCtx &ctx) {

            // origin guard
            if(not ctx.origin) {
                return;
            }

            auto const& log = log::http1;
            _deb("start: cx.meter_read %ldB, cx.meter_write %ldB", ctx.origin->meter_read_bytes, ctx.origin->meter_write_bytes);

            auto const& last_flow_entry = ctx.origin->flow().flow_queue().back();
            auto const& side = last_flow_entry.source();
            auto const& buffer = last_flow_entry.data();
            auto flow_pos = ctx.origin->flow().flow_queue().size() - 1;

            // limit this rather info/convenience regexing to 128 bytes

            // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
            // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
            // as there is nothing dependent on full URI and more can slow box down for not real benefit.

            if(side == 'r') {

                auto const buf_sz = buffer->size();
                _dia("start: flow block index %d, size %dB", flow_pos, buf_sz);
                if(ctx.new_data_check(flow_pos + 1, buf_sz)) {
                    ctx.update_seen_block(flow_pos + 1, buf_sz);
                    parse_request(ctx, buffer);
                }
            }

            _deb("start finished");
        }
    }

    namespace v2 {

        L7PayloadHints Http2Direction::observe(std::string_view data,
                                               bool client_side) {
            L7PayloadHints ranges;
            last_stream_ids_.clear();
            auto add_body = [&](std::size_t start, std::size_t end) {
                if(start == end) return;
                if(!ranges.empty() && ranges.back().second ==
                        static_cast<std::int64_t>(start) &&
                   last_stream_ids_.back() == current_stream_id_) {
                    ranges.back().second = static_cast<std::int64_t>(end);
                } else {
                    ranges.emplace_back(static_cast<std::int64_t>(start),
                                        static_cast<std::int64_t>(end));
                    last_stream_ids_.push_back(current_stream_id_);
                }
            };
            auto reset_frame = [&]() {
                header_size_ = 0;
                frame_remaining_ = 0;
                data_remaining_ = 0;
                padding_remaining_ = 0;
                data_frame_ = false;
                padded_ = false;
                need_padding_length_ = false;
            };

            if(opaque_) return {{-1, -1}};
            std::size_t cursor = 0;
            if(first_input_) {
                first_input_ = false;
                reading_preface_ = client_side && !data.empty() && data.front() == txt::magic[0];
            }
            while(cursor < data.size()) {
                if(reading_preface_) {
                    if(data[cursor] != txt::magic[preface_size_]) {
                        opaque_ = true;
                        break;
                    }
                    ++cursor;
                    if(++preface_size_ == txt::magic_sz) reading_preface_ = false;
                    continue;
                }
                if(header_size_ < header_.size()) {
                    header_[header_size_++] = static_cast<unsigned char>(data[cursor++]);
                    if(header_size_ != header_.size()) continue;
                    frame_remaining_ = (static_cast<std::uint32_t>(header_[0]) << 16U) |
                                       (static_cast<std::uint32_t>(header_[1]) << 8U) |
                                       static_cast<std::uint32_t>(header_[2]);
                    data_frame_ = header_[3] == 0;
                    current_stream_id_ =
                        (static_cast<std::uint32_t>(header_[5] & 0x7fU) << 24U) |
                        (static_cast<std::uint32_t>(header_[6]) << 16U) |
                        (static_cast<std::uint32_t>(header_[7]) << 8U) |
                        static_cast<std::uint32_t>(header_[8]);
                    padded_ = data_frame_ && (header_[4] & 0x08U) != 0;
                    need_padding_length_ = padded_;
                    data_remaining_ = data_frame_ && !padded_ ? frame_remaining_ : 0;
                    if(frame_remaining_ == 0) reset_frame();
                    continue;
                }
                if(need_padding_length_) {
                    const auto padding = static_cast<std::uint32_t>(
                        static_cast<unsigned char>(data[cursor++]));
                    if(frame_remaining_ == 0 || padding > frame_remaining_ - 1) {
                        opaque_ = true;
                        break;
                    }
                    --frame_remaining_;
                    padding_remaining_ = padding;
                    data_remaining_ = frame_remaining_ - padding;
                    need_padding_length_ = false;
                    continue;
                }
                if(data_remaining_ != 0) {
                    const auto count = std::min<std::size_t>(data_remaining_,
                                                             data.size() - cursor);
                    add_body(cursor, cursor + count);
                    cursor += count;
                    data_remaining_ -= static_cast<std::uint32_t>(count);
                    frame_remaining_ -= static_cast<std::uint32_t>(count);
                } else {
                    const auto count = std::min<std::size_t>(
                        frame_remaining_, data.size() - cursor);
                    cursor += count;
                    frame_remaining_ -= static_cast<std::uint32_t>(count);
                    if(padding_remaining_ >= count)
                        padding_remaining_ -= static_cast<std::uint32_t>(count);
                }
                if(frame_remaining_ == 0) reset_frame();
            }
            if(opaque_) return {{-1, -1}};
            return ranges.empty() ? L7PayloadHints{{0, 0}} : ranges;
        }

        void observe_content(EngineCtx& ctx, std::size_t direction,
                             std::string_view data, std::uint64_t read_bytes,
                             bool client_side) {
            auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
            if(!app || app->version != app_HttpRequest::HTTP_VER::HTTP2) return;
            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
            if(!connection) return;
            auto& tracker = connection->content_directions.at(direction);
            auto ranges = tracker.observe(data, client_side);
            std::vector<std::string> encodings;
            encodings.reserve(tracker.stream_ids().size());
            for(const auto stream_id : tracker.stream_ids()) {
                const auto stream = connection->streams.find(stream_id);
                encodings.push_back(stream != connection->streams.end() &&
                                    stream->second.content_encoding_ ==
                                        Http2Stream::content_type_t::GZIP
                                    ? "gzip" : "");
            }
            app->observe_l7_payload(data, read_bytes, std::move(ranges),
                                    std::move(encodings));
        }

        // Bound attacker-controlled inspection state independently of peer
        // transport limits.
        constexpr std::size_t max_pending_header_block_size = 1024 * 1024;
        constexpr std::size_t max_tracked_streams = 4096;
        constexpr std::size_t max_pending_settings = 1024;

        namespace {
            constexpr std::size_t default_max_frame_size = 16384;

            bool ascii_equal_ci(std::string_view left,
                                std::string_view right) noexcept {
                if(left.size() != right.size()) return false;
                for(std::size_t index = 0; index < left.size(); ++index) {
                    const auto l = static_cast<unsigned char>(left[index]);
                    const auto r = static_cast<unsigned char>(right[index]);
                    if(std::tolower(l) != std::tolower(r)) return false;
                }
                return true;
            }

            std::string_view trim_ows(std::string_view value) noexcept {
                while(!value.empty() &&
                      (value.front() == ' ' || value.front() == '\t'))
                    value.remove_prefix(1);
                while(!value.empty() &&
                      (value.back() == ' ' || value.back() == '\t'))
                    value.remove_suffix(1);
                return value;
            }

            struct delimiter_scan_t {
                std::size_t position = std::string_view::npos;
                bool valid = true;
            };

            delimiter_scan_t find_unquoted(std::string_view value,
                                           char delimiter) noexcept {
                bool quoted = false;
                bool escaped = false;
                for(std::size_t index = 0; index < value.size(); ++index) {
                    const char ch = value[index];
                    if(escaped) { escaped = false; continue; }
                    if(quoted && ch == '\\') { escaped = true; continue; }
                    if(ch == '"') { quoted = !quoted; continue; }
                    if(!quoted && ch == delimiter) return {index, true};
                }
                return {std::string_view::npos, !quoted && !escaped};
            }

            bool is_dns_message_media_type(std::string_view value) noexcept {
                value = trim_ows(value);
                const auto parameters = value.find(';');
                return ascii_equal_ci(trim_ows(value.substr(0, parameters)),
                                      "application/dns-message");
            }

            bool is_doh_path(std::string_view path) noexcept {
                constexpr std::string_view endpoint = "/dns-query";
                return path == endpoint ||
                    (path.size() > endpoint.size() &&
                     path.compare(0, endpoint.size(), endpoint) == 0 &&
                     path[endpoint.size()] == '?');
            }

            bool accepts_dns_message(std::string_view value) noexcept {
                auto quality_permits = [](std::string_view quality) noexcept {
                    quality = trim_ows(quality);
                    if(quality.empty()) return false;
                    const auto dot = quality.find('.');
                    auto whole = quality.substr(0, dot);
                    auto fraction = dot == std::string_view::npos
                        ? std::string_view{} : quality.substr(dot + 1);
                    if(whole.size() != 1 || fraction.size() > 3 ||
                       (dot != std::string_view::npos &&
                        quality.find('.', dot + 1) != std::string_view::npos) ||
                       !std::all_of(fraction.begin(), fraction.end(),
                                    [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) {
                        return false;
                    }
                    if(whole == "1")
                        return std::all_of(fraction.begin(), fraction.end(),
                                           [](unsigned char ch) { return ch == '0'; });
                    return whole == "0" &&
                        std::any_of(fraction.begin(), fraction.end(),
                                    [](unsigned char ch) { return ch >= '1' && ch <= '9'; });
                };
                while(true) {
                    const auto comma_scan = find_unquoted(value, ',');
                    if(!comma_scan.valid) return false;
                    const auto comma = comma_scan.position;
                    auto item = trim_ows(value.substr(0, comma));
                    if(is_dns_message_media_type(item)) {
                        bool permitted = true;
                        bool quality_seen = false;
                        auto parameter_scan = find_unquoted(item, ';');
                        if(!parameter_scan.valid) permitted = false;
                        auto parameter = parameter_scan.position;
                        while(permitted && parameter != std::string_view::npos) {
                            item.remove_prefix(parameter + 1);
                            const auto next_scan = find_unquoted(item, ';');
                            if(!next_scan.valid) { permitted = false; break; }
                            const auto next = next_scan.position;
                            auto part = trim_ows(item.substr(0, next));
                            const auto equals = part.find('=');
                            if(equals != std::string_view::npos &&
                               ascii_equal_ci(trim_ows(part.substr(0, equals)), "q")) {
                                if(quality_seen) permitted = false;
                                quality_seen = true;
                                permitted = permitted && quality_permits(part.substr(equals + 1));
                            }
                            parameter = next;
                        }
                        if(permitted) return true;
                    }
                    if(comma == std::string_view::npos) return false;
                    value.remove_prefix(comma + 1);
                }
            }

            bool append_frame(std::string& output, uint8_t type, uint8_t flags,
                              uint32_t stream_id, std::string_view payload) {
                if(payload.size() > 0x00ffffffU || stream_id > 0x7fffffffU) {
                    return false;
                }

                output.push_back(static_cast<char>((payload.size() >> 16) & 0xff));
                output.push_back(static_cast<char>((payload.size() >> 8) & 0xff));
                output.push_back(static_cast<char>(payload.size() & 0xff));
                output.push_back(static_cast<char>(type));
                output.push_back(static_cast<char>(flags));
                output.push_back(static_cast<char>((stream_id >> 24) & 0x7f));
                output.push_back(static_cast<char>((stream_id >> 16) & 0xff));
                output.push_back(static_cast<char>((stream_id >> 8) & 0xff));
                output.push_back(static_cast<char>(stream_id & 0xff));
                output.append(payload.data(), payload.size());
                return true;
            }

            void append_u32(std::string& output, uint32_t value) {
                output.push_back(static_cast<char>((value >> 24) & 0xff));
                output.push_back(static_cast<char>((value >> 16) & 0xff));
                output.push_back(static_cast<char>((value >> 8) & 0xff));
                output.push_back(static_cast<char>(value & 0xff));
            }
        }

        std::optional<std::string> make_response(long stream_id,
                                                 std::string_view body,
                                                 unsigned status,
                                                 bool head_only) {
#ifdef USE_HPACK
            if(stream_id <= 0 || stream_id > 0x7fffffffL || (stream_id & 1) == 0 ||
               status < 100 || status > 999) {
                return std::nullopt;
            }

            HPACK::encoder_t encoder(0);
            // Replacement terminates the connection with GOAWAY. Start its
            // standalone HPACK block by clearing dynamic state, then avoid
            // entries which could violate SETTINGS_HEADER_TABLE_SIZE = 0.
            encoder.add(":status", std::to_string(status), false, true);
            encoder.add("content-type", "text/html; charset=utf-8", false, true);
            encoder.add("content-length", std::to_string(body.size()), false, true);
            encoder.add("cache-control", "no-store", false, true);

            std::vector<uint8_t> encoded {0x20}; // dynamic table size update: 0
            auto const& fields = encoder.data();
            encoded.insert(encoded.end(), fields.begin(), fields.end());
            std::string output = make_server_preamble();
            auto const wire_body_size = head_only ? 0 : body.size();
            output.reserve(9 + encoded.size() + wire_body_size +
                           9 * ((wire_body_size + default_max_frame_size - 1) /
                                default_max_frame_size));
            auto const header_flags = static_cast<uint8_t>(
                0x04 | (body.empty() || head_only ? 0x01 : 0));
            std::string_view header_block(
                reinterpret_cast<char const*>(encoded.data()), encoded.size());
            if(!append_frame(output, 1, header_flags, static_cast<uint32_t>(stream_id),
                             header_block)) {
                return std::nullopt;
            }

            std::size_t offset = 0;
            while(!head_only && offset < body.size()) {
                auto const length = std::min(default_max_frame_size, body.size() - offset);
                auto const final = offset + length == body.size();
                if(!append_frame(output, 0, final ? 0x01 : 0x00,
                                 static_cast<uint32_t>(stream_id), body.substr(offset, length))) {
                    return std::nullopt;
                }
                offset += length;
            }
            return output;
#else
            (void)stream_id;
            (void)body;
            (void)status;
            (void)head_only;
            return std::nullopt;
#endif
        }

        std::string make_server_preamble() {
            std::string output;
            append_frame(output, 4, 0, 0, {}); // server SETTINGS
            append_frame(output, 4, 1, 0, {}); // acknowledge client SETTINGS
            return output;
        }

        std::string make_goaway(uint32_t last_stream_id, uint32_t error_code,
                                std::string_view debug_data) {
            std::string payload;
            payload.reserve(8 + debug_data.size());
            append_u32(payload, last_stream_id & 0x7fffffffU);
            append_u32(payload, error_code);
            payload.append(debug_data.data(), debug_data.size());

            std::string output;
            append_frame(output, 7, 0, 0, payload);
            return output;
        }

        const char* frame_type_str(uint8_t t) {
            switch (t) {
                case 16:
                    return "priority-update";

                case 12:
                    return "origin";

                case 10:
                    return "altsvc";
                case 9:
                    return "continuation";
                case 8:
                    return "window-update";
                case 7:
                    return "goaway";
                case 6:
                    return "ping";
                case 5:
                    return "push-promise";
                case 4:
                    return "settings";
                case 3:
                    return "rst-stream";
                case 2:
                    return "priority";
                case 1:
                    return "headers";
                case 0:
                    return "data";
                default:
                    return "unknown";
            }
        }

        std::size_t find_magic(buffer& frame) {
            auto const& log = log::http2;

            std::size_t to_ret_index = 0L;

            auto magic_view = frame.view(0, txt::magic_sz);

            auto str = magic_view.string_view();
            auto pos = str.find(txt::magic);

            if(pos != str.npos) {
                _dia("find_magic: found magic!");
                to_ret_index += txt::magic_sz;
            } else {
                _deb("find_magic: no magic");
            }

            return to_ret_index;
        }

        std::optional<uint32_t> find_frame_sz(buffer const& frame) {

            if(frame.size() < 4) return 0;

            auto const& log = log::http2;

            unsigned int cur_off = 0;

            buffer a(4);

            a.size(4);
            a.at(0) = 0;
            a.at(1) = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);
            a.at(2) = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);
            a.at(3) = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);


            _deb("frame size bytes: %s", hex_print(a.data(),a.size()).c_str());

            auto siz = ntohl(a.get_at<uint32_t>(0));

            return siz;
        }


        void fill_kb(EngineCtx& ctx, side_t side, std::shared_ptr<app_HttpRequest> const& app_data,
                        long stream_id, uint8_t flags, buffer const& data) {

            auto *state_data = std::any_cast<Http2Connection>(&ctx.state_data);
            if (state_data) {
                auto &stream_state = state_data->streams[stream_id];

                auto kb = sx::KB::get();
                auto lc_ = std::scoped_lock(sx::KB::lock());

                auto domain = stream_state.domain();
                auto hostname = stream_state.hostname();

                if(not domain or not hostname) return;

                auto domain_entry = kb->at<KB_String>(stream_state.domain().value_or("."));
                auto host_entry = domain_entry->at<KB_String>(stream_state.hostname().value_or("<?>"));


                if (auto path = stream_state.request_header(":path"); path.has_value()) {
                    auto path_entry = host_entry->at<KB_String>(path.value());

                    if(side == side_t::LEFT) {

                        if (auto ck = stream_state.request_header("cookie"); ck.has_value()) {
                            auto cookies = host_entry->at<KB_String>("cookie");
                            auto ck_entry = cookies->at<KB_String>("@" + std::to_string(time(nullptr)),
                                                                   ck.value());
                        }

                    } else {

                        if(auto code = stream_state.response_header(":status"); code.has_value())  {
                            auto status = path_entry->at<KB_Int>(":status", safe_val(code.value()));
                            auto cnt = status->at<KB_Int>("counter", 0);
                            auto* kb_int = (KB_Int*) cnt->data.get();
                            kb_int->value++;
                        }
                        if(auto set_cookie = stream_state.response_header("set-cookie"); set_cookie) {
                            auto sc = path_entry->at<KB_String>("set-cookie");
                            sc->at<KB_String>("@"+std::to_string(time(nullptr)), set_cookie.value());
                        }
                    }
                }
            }
        }

        void detect_app(EngineCtx& ctx, side_t side, std::shared_ptr<app_HttpRequest> const& app_data,
                        long stream_id, uint8_t flags, buffer const& data) {

            (void)app_data;

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
            if(state_data) {
                auto &stream_state = state_data->streams[stream_id];

                if(side == side_t::LEFT) {
                    auto const method = stream_state.request_header(":method");
                    if(auto path = stream_state.request_header(":path");
                       path && method &&
                       (*method == "GET" || *method == "POST") &&
                       is_doh_path(*path)) {
                        stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                    }
                    else if(auto accept = stream_state.request_headers_.find("accept");
                            accept != stream_state.request_headers_.end()) {
                        if(std::any_of(accept->second.begin(), accept->second.end(),
                               [](std::string const& value) {
                                   return accepts_dns_message(value);
                               })) {
                            stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                        }
                    }
                } else if(auto content_type =
                              stream_state.response_header("content-type");
                          content_type && is_dns_message_media_type(*content_type)) {
                    stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                }
            }
        }

        void process_header_entry(EngineCtx& ctx, side_t side, std::shared_ptr<app_HttpRequest> const& app_data,
                                  long stream_id, uint8_t flags, buffer const& data, std::string const& hdr, std::string const& hdr_elem) {
            auto const& log = log::http2_headers;

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);

            auto arrow = arrow_from_side(side);
            _dia("Frame<%ld>: %c%c header/%s : %s", stream_id,
                        arrow, arrow,
                        escape(hdr).c_str(), escape(hdr_elem).c_str());
            if(state_data) {

                auto& stream_state = state_data->streams[stream_id];

                auto touch_header = [&](const char* hdr_name, bool clear = false) {
                    auto& headers = side == side_t::LEFT ? stream_state.request_headers_ : stream_state.response_headers_;

                    if(clear)
                        headers[hdr_name].clear();
                    headers[hdr_name].emplace_back(hdr_elem);
                };


                if(side == side_t::LEFT) {

                    if (hdr == ":authority") {
                        touch_header(":authority", true);
                        if (app_data) {
                            app_data->http_data.clear();

                            app_data->http_data.host = hdr_elem;
                        }
                    } else if (hdr == ":scheme") {
                        if (app_data) app_data->http_data.proto = hdr_elem + "://";
                    } else if (hdr == ":path") {
                        if (app_data) {
                            app_data->http_data.uri = hdr_elem;

                            // mark this request as fully populated
                            app_data->mark_populated();
                            _dia("Frame<%ld>: %c%c: app data populated", stream_id, arrow, arrow);


                            auto load_from_props = [&](auto header, std::string& where) {

                                if(not where.empty()) return;

                                auto it = app_data->properties().find(header);
                                if(it != app_data->properties().end()) {
                                     where = it->second;
                                    _dia("Frame<%ld>: %c%c: '%s' recovered from properties", stream_id, arrow, arrow, header);
                                }

                            };
                            // now fix up authority from props
                            load_from_props(":authority", app_data->http_data.host);
                            load_from_props(":method", app_data->http_data.method);
                            load_from_props(":referer", app_data->http_data.referer);

                            if(app_data->http_data.proto.empty()) {
                                if(auto const scheme = app_data->properties().find(":scheme");
                                   scheme != app_data->properties().end()) {
                                    app_data->http_data.proto = scheme->second + "://";
                                }
                            }
                        }

                    } else if (hdr == ":method") {
                        if (app_data) app_data->http_data.method = hdr_elem;
                    }

                    // save all left (request) values
                    app_data->properties()[hdr] = hdr_elem;

                }
                else {
                    if(hdr == "content-encoding") {
                        if(hdr_elem == "gzip") stream_state.content_encoding_ = Http2Stream::content_type_t::GZIP;
                    }
                }
                touch_header(hdr.c_str());
            }
        }

        bool finalize_doh_response(EngineCtx& ctx, Http2Stream& stream) {
            if(stream.sub_app_ != Http2Stream::sub_app_t::DNS ||
               stream.doh_response_finished_) {
                return !stream.response_invalid_;
            }
            stream.doh_response_finished_ = true;

            auto content_type = stream.response_header("content-type")
                .value_or(std::string{});
            bool const response_content_type = !content_type.empty();
            bool dns_media_type = response_content_type
                ? is_dns_message_media_type(content_type) : false;
            if(!response_content_type) {
                if(auto accept = stream.request_headers_.find("accept");
                   accept != stream.request_headers_.end()) {
                    dns_media_type = std::any_of(
                        accept->second.begin(), accept->second.end(),
                        [](std::string const& value) {
                            return accepts_dns_message(value);
                        });
                }
            }
            if(!dns_media_type) {
                stream.doh_response_body_.clear();
                return true;
            }

            auto response = std::make_shared<DNS_Response>();
            const auto parsed = response->load(&stream.doh_response_body_);
            if(!parsed || *parsed != stream.doh_response_body_.size() ||
               (response->flags() & 0x8000U) == 0) {
                stream.response_invalid_ = true;
                stream.doh_response_body_.clear();
                return false;
            }

            DNS_Inspector::store(response);
            if(auto http = std::dynamic_pointer_cast<app_HttpRequest>(
                   ctx.application_data)) {
                http->http_data.sub_proto = "dns";
            }
            stream.doh_response_body_.clear();
            return true;
        }

        void process_headers(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {

#ifdef USE_HPACK
            if(data.empty()) return;

            auto const& log = log::http2_headers;

            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
            if (!connection) {
                ctx.state_data = std::make_any<Http2Connection>();
                connection = std::any_cast<Http2Connection>(&ctx.state_data);
            }
            if(connection->connection_invalid) return;
            if(data.size() > max_pending_header_block_size) {
                _err("complete HTTP/2 header block exceeds inspection limit");
                connection->connection_invalid = true;
                return;
            }
            auto& decoder = side == side_t::LEFT
                            ? connection->request_decoder
                            : connection->response_decoder;
            // Decode against a candidate copy. A malformed block must not
            // partially mutate the connection-wide dynamic table.
            auto candidate = std::make_unique<HPACK::decoder_t>(*decoder);
            auto data_string = std::string((const char*)data.data(), data.size());
            auto vec = std::vector<uint8_t>(data_string.begin(), data_string.end());

            if(not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }
            auto my_app_data = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
            if(my_app_data) my_app_data->version = app_HttpRequest::HTTP_VER::HTTP2;

            try {
                if (not candidate->decode(vec)) {
                    _err("Frame: hpack decode error");
                    connection->connection_invalid = true;
                    return;
                }
            } catch (std::exception const& e) {
                _err("Frame: hpack decode exception: %s", e.what());
                connection->connection_invalid = true;
                return;
            }

            decoder = std::move(candidate);

            std::optional<sx::ja4::HTTP> ja4h;
            if(ctx.options.http.ja4h) {
                ja4h = sx::ja4::HTTP();
                ja4h->version = "20";
            }


            for (auto& [ hdr, vlist ] : decoder->headers()) {
                for(auto const& hdr_elem: vlist) {
                    process_header_entry(ctx, side, my_app_data,
                                         stream_id, flags, data, hdr, hdr_elem);
                    if(ja4h.has_value()) {
                        std::string_view view_to_hdr = hdr;
                        std::string_view view_to_hdr_elem = hdr_elem;

                        ja4h->process_header_pair(std::make_pair(view_to_hdr, view_to_hdr_elem));
                    }
                }
            }
            if(ja4h.has_value()) {
                auto meth = my_app_data->http_data.method;
                if(meth.size() >= 2)
                    ja4h->cmd = sx::ja4::util::to_lower(meth).substr(0,2);

                my_app_data->http_data.ja4h = ja4h->ja4h();
            }

            detect_app(ctx, side, my_app_data, stream_id, flags, data);
            if(side == side_t::LEFT) {
                connection->latest_request_stream_id = stream_id;
                if(ctx.origin) {
                    ctx.origin->replacement_type(MitmHostCX::REPLACETYPE_HTTP2);
                }
            }
            if(ctx.origin && ctx.origin->opt_kb_enabled) {
                fill_kb(ctx, side, my_app_data, stream_id, flags, data);
            }
#endif
        }

        bool synchronize_headers_impl(EngineCtx& ctx, side_t side,
                                      buffer const& data,
                                      bool validate_push_promise) {
#ifdef USE_HPACK
            auto const& log = log::http2_headers;
            if(data.empty() || data.size() > max_pending_header_block_size)
                return false;
            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
            if(!connection) {
                ctx.state_data = std::make_any<Http2Connection>();
                connection = std::any_cast<Http2Connection>(&ctx.state_data);
            }
            auto& decoder = side == side_t::LEFT
                ? *connection->request_decoder : *connection->response_decoder;
            std::vector<uint8_t> encoded(
                static_cast<uint8_t const*>(data.data()),
                static_cast<uint8_t const*>(data.data()) + data.size());
            try {
                if(!decoder.decode(encoded)) {
                    _err("Frame: hpack synchronization decode error");
                    if(decoder.failure() != HPACK::decoder_t::failure_t::header_semantics)
                        connection->connection_invalid = true;
                    return false;
                }
            } catch(std::exception const& error) {
                _err("Frame: hpack synchronization exception: %s", error.what());
                connection->connection_invalid = true;
                return false;
            }

            // H2-056/H2-057 need the compression context updated even when
            // the stream is semantically refused. PUSH_PROMISE semantic
            // validation belongs to the later HTTP/2 validation tranche.
            (void)validate_push_promise;
            return true;
#else
            (void)ctx; (void)side; (void)data; (void)validate_push_promise;
            return false;
#endif
        }

        void synchronize_headers(EngineCtx& ctx, side_t side,
                                 buffer const& data) {
            (void)synchronize_headers_impl(ctx, side, data, false);
        }

        void process_data(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
//            auto const &log = log::http2;
            auto const& log = log::http2;

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
            if(state_data) {
                auto stream_it = state_data->streams.find(stream_id);
                if(stream_it == state_data->streams.end()) {
                    const auto id = static_cast<uint32_t>(stream_id);
                    const bool previously_opened = (id & 1U) != 0
                        ? id <= state_data->highest_client_stream_id
                        : id <= state_data->highest_promised_stream_id;
                    if(previously_opened) {
                        _err("Frame: DATA on closed HTTP/2 stream");
                    } else {
                        _err("Frame: DATA on idle HTTP/2 stream");
                        state_data->connection_invalid = true;
                    }
                    return;
                }
                if(side == side_t::LEFT
                        ? stream_it->second.request_headers_.empty()
                        : stream_it->second.response_headers_.empty()) {
                    _err("Frame: DATA before initial HTTP/2 headers");
                    if(side == side_t::LEFT)
                        stream_it->second.request_invalid_ = true;
                    else
                        stream_it->second.response_invalid_ = true;
                    return;
                }
                auto& stream_state = stream_it->second;
                if(side == side_t::LEFT ? stream_state.request_ended_
                                        : stream_state.response_ended_) {
                    _err("Frame: DATA after HTTP/2 stream direction ended");
                    return;
                }
                if(side == side_t::LEFT ? stream_state.request_invalid_
                                        : stream_state.response_invalid_) {
                    _err("Frame: DATA on invalid HTTP/2 stream direction");
                    return;
                }

                if(data.empty() && (flags & 0x01U) == 0) return;

                if(!data.empty()) {
                    if(auto app = std::dynamic_pointer_cast<app_HttpRequest>(
                           ctx.application_data)) {
                        app->observe_l7_encoding(
                            stream_state.content_encoding_ ==
                                    Http2Stream::content_type_t::GZIP
                                ? "gzip" : "");
                    }
                }

                if(stream_state.content_encoding_ == Http2Stream::content_type_t::GZIP) {
//                    auto& gz_instance = state_data->streams[stream_id].gzip;
//
//                    if(gz_instance.has_value() and (flags & 0x01u) != 0) {
//
//                        // fixme: add configurable uncompress features
//                        auto const& compressed_data = state_data->streams[stream_id].gzip.in;
//
//                        buffer out;
//                        out.capacity(compressed_data.size() * 15);
//                        unsigned long outlen = out.capacity();
//                        int uc_result = uncompress(out.data(), &outlen, (unsigned char*)compressed_data.data(), compressed_data.size());
//
//                        if(uc_result == Z_OK) {
//                            out.size(outlen);
//                            _deb("Gunzip: \r\n%s", hex_dump(out, 4, 0, true).c_str());
//                        } else {
//                            _deb("Gunzip: failed");
//                        }
//
//                    }
//                    else {
//                        _dia("process_data/gzip (cont)");
//                        if(auto& gz_instance = state_data->streams[stream_id].gzip; gz_instance.has_value()) {
//                            gz_instance->in.append(data);
//                        }
//                    }
                }

                switch (stream_state.sub_app_) {

                    case Http2Stream::sub_app_t::DNS:
                        if(side == side_t::RIGHT) {
                            constexpr std::size_t maximum_dns_wire_size = 65535;
                            if(stream_state.doh_response_finished_ ||
                               data.size() > maximum_dns_wire_size -
                                   stream_state.doh_response_body_.size()) {
                                _err("DNS response: invalid or oversized HTTP/2 body");
                                stream_state.response_invalid_ = true;
                                return;
                            }
                            stream_state.doh_response_body_.append(data);
                            if(ctx.origin)
                                ctx.origin->acknowledge_continuous_mode(5000);
                            if((flags & 0x01U) != 0 &&
                               !finalize_doh_response(ctx, stream_state)) {
                                _err("DNS response: malformed HTTP/2 body");
                                return;
                            }
                        }
                        break;


                    case Http2Stream::sub_app_t::UNKNOWN:
                    default:
                        ;
                }

                if((flags & 0x01U) != 0) {
                    if(side == side_t::LEFT)
                        stream_state.request_ended_ = true;
                    else
                        stream_state.response_ended_ = true;
                    if(stream_state.request_ended_ && stream_state.response_ended_) {
                        state_data->streams.erase(stream_it);
                        if(state_data->latest_request_stream_id == stream_id)
                            state_data->latest_request_stream_id = -1;
                    }
                }
            }
        }

        bool ping_acknowledges_liveness(side_t side, long stream_id,
                                        uint8_t flags,
                                        std::size_t payload_size) noexcept {
            constexpr uint8_t flag_ack = 0x01;
            return side == side_t::RIGHT && stream_id == 0 &&
                   payload_size == 8 && (flags & flag_ack) != 0;
        }

        void process_ping(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
            constexpr uint8_t flag_ack = 0x01;
            constexpr std::size_t max_pending_pings = 64;
            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
            if(!connection || stream_id != 0 || data.size() != 8)
                return;

            std::array<unsigned char, 8> opaque{};
            std::copy_n(static_cast<unsigned char const*>(data.data()),
                        opaque.size(), opaque.begin());

            if(side == side_t::LEFT && (flags & flag_ack) == 0) {
                if(connection->client_pings_pending.size() == max_pending_pings)
                    connection->client_pings_pending.pop_front();
                connection->client_pings_pending.push_back(opaque);
                return;
            }

            if(!ping_acknowledges_liveness(side, stream_id, flags, data.size()))
                return;
            auto matching = std::find(connection->client_pings_pending.begin(),
                                      connection->client_pings_pending.end(), opaque);
            if(matching == connection->client_pings_pending.end()) return;
            connection->client_pings_pending.erase(matching);

            if(ctx.origin) {
                auto const& log = log::http2_frames;
                _deb("matching ping answer - enable continuous mode");
                ctx.origin->acknowledge_continuous_mode(5000);
            }
        }

        void process_other(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
            if(data.empty()) return;
        }

        std::size_t process_frame(EngineCtx& ctx, side_t side, buffer& frame) {
            constexpr size_t preamble_sz = 9L;
            constexpr uint8_t flag_end_headers = 0x04;
            if(frame.size() < preamble_sz) return 0L;

            auto const& log = log::http2_frames;

            auto frame_sz_opt = find_frame_sz(frame);

            // not possible to parse frame header
            if(not frame_sz_opt) return 0L;
            auto frame_sz = frame_sz_opt.value();

            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
            if(!connection) {
                ctx.state_data = std::make_any<Http2Connection>();
                connection = std::any_cast<Http2Connection>(&ctx.state_data);
            }
            // Reject an impossible advertised length from its 9-byte header;
            // do not buffer up to 16 MiB behind the default 16 KiB limit.
            const auto frame_limit = side == side_t::LEFT
                ? connection->left_max_frame_size
                : connection->right_max_frame_size;
            if(frame_sz > frame_limit) {
                _err("Frame: size %u exceeds peer-advertised limit %u",
                     frame_sz, frame_limit);
                connection->connection_invalid = true;
                connection->request_headers_pending.clear();
                connection->response_headers_pending.clear();
                return frame.size();
            }

            std::size_t cur_off = 3L;
            if (frame_sz + preamble_sz <= frame.size()) {
                auto typ = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);

                auto flg = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);
                auto stream_id = static_cast<long>(
                    ntohl(frame.get_at<uint32_t>(cur_off)) & 0x7fffffffU);
                cur_off += sizeof(uint32_t);

                // end of preamble

                // These frame-shape violations are connection errors. Do not
                // let later bytes regain HTTP semantics after mandatory close.
                const bool invalid_frame_shape =
                    ((typ == 0 || typ == 1 || typ == 9) && stream_id == 0) ||
                    (typ == 2 && (stream_id == 0 || frame_sz != 5)) ||
                    (typ == 3 && (stream_id == 0 || frame_sz != 4)) ||
                    (typ == 6 && (stream_id != 0 || frame_sz != 8)) ||
                    (typ == 7 && (stream_id != 0 || frame_sz < 8)) ||
                    (typ == 8 && frame_sz != 4);
                if(invalid_frame_shape) {
                    _err("Frame: invalid HTTP/2 %s shape (size=%u stream=%ld)",
                         frame_type_str(typ), frame_sz, stream_id);
                    connection->connection_invalid = true;
                    connection->request_headers_pending.clear();
                    connection->response_headers_pending.clear();
                    return preamble_sz + frame_sz;
                }

                if(typ == 4) {
                    constexpr uint8_t flag_ack = 0x01;
                    if(stream_id != 0 ||
                       ((flg & flag_ack) != 0 && frame_sz != 0) ||
                       ((flg & flag_ack) == 0 && frame_sz % 6 != 0)) {
                        _err("Frame: malformed HTTP/2 SETTINGS");
                        connection->connection_invalid = true;
                        return preamble_sz + frame_sz;
                    }
                    auto& acknowledged = side == side_t::LEFT
                        ? connection->right_settings_awaiting_ack
                        : connection->left_settings_awaiting_ack;
                    if((flg & flag_ack) != 0) {
                        if(acknowledged == 0) {
                            _err("Frame: unsolicited HTTP/2 SETTINGS ACK");
                            connection->connection_invalid = true;
                            return preamble_sz + frame_sz;
                        }
                        --acknowledged;
#ifdef USE_HPACK
                        auto& pending_tables = side == side_t::LEFT
                            ? connection->right_header_table_settings_pending
                            : connection->left_header_table_settings_pending;
                        if(pending_tables.empty()) {
                            _err("Frame: missing HTTP/2 SETTINGS state for ACK");
                            connection->connection_invalid = true;
                            return preamble_sz + frame_sz;
                        }
                        auto values = std::move(pending_tables.front());
                        pending_tables.pop_front();
                        auto& constrained_decoder = side == side_t::LEFT
                            ? connection->request_decoder
                            : connection->response_decoder;
                        for(auto value: values)
                            constrained_decoder->maximum_table_size(value);
#endif
                    } else {
                        auto& awaiting = side == side_t::LEFT
                            ? connection->left_settings_awaiting_ack
                            : connection->right_settings_awaiting_ack;
                        if(awaiting >= max_pending_settings) {
                            _err("Frame: too many unacknowledged HTTP/2 SETTINGS");
                            connection->connection_invalid = true;
                            return preamble_sz + frame_sz;
                        }
                        ++awaiting;

#ifdef USE_HPACK
                        std::vector<uint32_t> header_table_values;
#endif
                        uint32_t proposed_max = side == side_t::LEFT
                            ? connection->right_max_frame_size
                            : connection->left_max_frame_size;
                        bool proposed_push = connection->server_push_enabled;
                        bool proposed_extended_connect = connection->extended_connect_enabled;
                        uint32_t proposed_concurrent = side == side_t::LEFT
                            ? connection->max_server_streams
                            : connection->max_client_streams;
                        std::int64_t proposed_initial_window = side == side_t::LEFT
                            ? connection->server_initial_stream_window
                            : connection->client_initial_stream_window;
                        for(std::size_t offset = 0; offset < frame_sz; offset += 6) {
                            const auto setting_id = ntohs(
                                frame.get_at<uint16_t>(preamble_sz + offset));
                            const auto value = ntohl(
                                frame.get_at<uint32_t>(preamble_sz + offset + 2));
#ifdef USE_HPACK
                            if(setting_id == 1)
                                header_table_values.push_back(value);
#endif
                            if(setting_id == 2) {
                                if(value > 1 || side == side_t::RIGHT) {
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                proposed_push = value != 0;
                            }
                            if(setting_id == 3) proposed_concurrent = value;
                            if(setting_id == 4) {
                                if(value > 0x7fffffffU) {
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                proposed_initial_window = value;
                            }
                            if(setting_id == 8) {
                                if(value > 1 ||
                                   (side == side_t::RIGHT &&
                                    proposed_extended_connect && value == 0)) {
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                if(side == side_t::RIGHT)
                                    proposed_extended_connect = value != 0;
                            }
                            if(setting_id == 5) {
                                if(value < 16384U || value > 0x00ffffffU) {
                                    _err("Frame: invalid HTTP/2 SETTINGS_MAX_FRAME_SIZE");
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                proposed_max = value;
                            }
                        }
                        const auto old_initial_window = side == side_t::LEFT
                            ? connection->server_initial_stream_window
                            : connection->client_initial_stream_window;
                        const auto window_delta = proposed_initial_window - old_initial_window;
                        constexpr std::int64_t maximum_flow_window = 0x7fffffffLL;
                        for(auto const& [id, stream]: connection->streams) {
                            (void)id;
                            const auto adjusted = (side == side_t::LEFT
                                ? stream.response_flow_window_
                                : stream.request_flow_window_) + window_delta;
                            if(adjusted > maximum_flow_window) {
                                connection->connection_invalid = true;
                                return preamble_sz + frame_sz;
                            }
                        }
                        if(side == side_t::LEFT) {
                            for(auto const& [id, window]:
                                connection->promised_flow_windows) {
                                (void)id;
                                if(window + window_delta > maximum_flow_window) {
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                            }
                        }
                        for(auto& [id, stream]: connection->streams) {
                            (void)id;
                            auto& window = side == side_t::LEFT
                                ? stream.response_flow_window_
                                : stream.request_flow_window_;
                            window += window_delta;
                        }
                        if(side == side_t::LEFT) {
                            for(auto& [id, window]: connection->promised_flow_windows) {
                                (void)id;
                                window += window_delta;
                            }
                            connection->server_initial_stream_window = proposed_initial_window;
                        } else {
                            connection->client_initial_stream_window = proposed_initial_window;
                        }

                        if(side == side_t::LEFT) {
                            connection->right_max_frame_size = proposed_max;
                            connection->server_push_enabled = proposed_push;
                            connection->max_server_streams = proposed_concurrent;
                        } else {
                            connection->left_max_frame_size = proposed_max;
                            connection->max_client_streams = proposed_concurrent;
                            connection->extended_connect_enabled = proposed_extended_connect;
                        }
#ifdef USE_HPACK
                        auto& pending_tables = side == side_t::LEFT
                            ? connection->left_header_table_settings_pending
                            : connection->right_header_table_settings_pending;
                        pending_tables.push_back(std::move(header_table_values));
#endif
                    }
                }

                if(typ == 7) {
                    const auto last_stream_id = ntohl(
                        frame.get_at<uint32_t>(preamble_sz)) & 0x7fffffffU;
                    const auto peer_initiated_parity = side == side_t::RIGHT
                        ? 1U : 0U;
                    if(last_stream_id != 0 &&
                       (last_stream_id & 1U) != peer_initiated_parity) {
                        _err("Frame: HTTP/2 GOAWAY boundary belongs to sender");
                        connection->connection_invalid = true;
                        return preamble_sz + frame_sz;
                    }
                    auto& prior = side == side_t::RIGHT
                        ? connection->server_goaway_last_stream_id
                        : connection->client_goaway_last_stream_id;
                    if(prior && last_stream_id > *prior) {
                        _err("Frame: increasing HTTP/2 GOAWAY last-stream-id");
                        connection->connection_invalid = true;
                        return preamble_sz + frame_sz;
                    }
                    prior = last_stream_id;

                    if(side == side_t::RIGHT) {
                        auto& pending = connection->request_headers_pending;
                        if(pending.active() &&
                           static_cast<uint32_t>(pending.stream_id) > last_stream_id) {
                            pending.decode_only = true;
                            connection->refused_client_streams.insert(
                                static_cast<uint32_t>(pending.stream_id));
                        }
                    } else {
                        for(auto it = connection->promised_streams.begin();
                            it != connection->promised_streams.end();) {
                            const auto promised = *it;
                            if(promised > last_stream_id) {
                                connection->refused_promised_streams.insert(promised);
                                connection->active_promised_streams.erase(promised);
                                connection->promised_flow_windows.erase(promised);
                                it = connection->promised_streams.erase(it);
                            } else {
                                ++it;
                            }
                        }
                    }
                }

                if(typ == 8) {
                    const auto increment = ntohl(
                        frame.get_at<uint32_t>(preamble_sz)) & 0x7fffffffU;
                    auto stream = connection->streams.find(stream_id);
                    if(increment == 0) {
                        _err("Frame: zero HTTP/2 WINDOW_UPDATE increment");
                        if(stream_id == 0) {
                            connection->connection_invalid = true;
                        } else if(stream != connection->streams.end()) {
                            stream->second.request_invalid_ = true;
                            stream->second.response_invalid_ = true;
                        } else {
                            const auto id = static_cast<uint32_t>(stream_id);
                            const bool previously_opened = (id & 1U) != 0
                                ? id <= connection->highest_client_stream_id
                                : id <= connection->highest_promised_stream_id;
                            if(!previously_opened)
                                connection->connection_invalid = true;
                        }
                        return preamble_sz + frame_sz;
                    }

                    constexpr std::int64_t maximum_flow_window = 0x7fffffffLL;
                    if(stream_id == 0) {
                        auto& window = side == side_t::LEFT
                            ? connection->server_connection_window
                            : connection->client_connection_window;
                        if(window > maximum_flow_window - increment) {
                            connection->connection_invalid = true;
                            return preamble_sz + frame_sz;
                        }
                        window += increment;
                    } else if(stream != connection->streams.end()) {
                        auto& window = side == side_t::LEFT
                            ? stream->second.response_flow_window_
                            : stream->second.request_flow_window_;
                        if(window > maximum_flow_window - increment) {
                            if(side == side_t::LEFT)
                                stream->second.response_invalid_ = true;
                            else
                                stream->second.request_invalid_ = true;
                            return preamble_sz + frame_sz;
                        }
                        window += increment;
                    } else {
                        const auto id = static_cast<uint32_t>(stream_id);
                        const bool previously_opened = (id & 1U) != 0
                            ? id <= connection->highest_client_stream_id
                            : id <= connection->highest_promised_stream_id;
                        if(!previously_opened)
                            connection->connection_invalid = true;
                    }
                    return preamble_sz + frame_sz;
                }

                uint32_t stream_dep = 0L;
                uint8_t wgh = 0;
                std::size_t payload_offset = preamble_sz;
                std::size_t payload_size = frame_sz;
                std::size_t padding_size = 0;

                if ((typ == 0 || typ == 1 || typ == 5) && (flg & 0x08)) {
                    if (payload_size < 1)
                        return preamble_sz + frame_sz;
                    padding_size = frame.get_at<uint8_t>(payload_offset++);
                    --payload_size;
                }

                if(typ == 1 && (flg & 0x20)) {
                    if (payload_size < 5)
                        return preamble_sz + frame_sz;
                    stream_dep = ntohl(frame.get_at<uint32_t>(payload_offset));
                    payload_offset += sizeof(uint32_t);
                    wgh = frame.get_at<uint8_t>(payload_offset++);
                    payload_size -= 5;
                }

                // A stream cannot depend on itself. Do not publish
                // headers from a frame the endpoint rejects as a connection error.
                if(typ == 1 && (flg & 0x20) &&
                   (stream_dep & 0x7fffffffU) == static_cast<uint32_t>(stream_id)) {
                    _err("Frame: HTTP/2 stream depends on itself");
                    if(auto* connection = std::any_cast<Http2Connection>(&ctx.state_data)) {
                        auto& pending = side == side_t::LEFT
                            ? connection->request_headers_pending
                            : connection->response_headers_pending;
                        pending.clear();
                        connection->connection_invalid = true;
                    }
                    return preamble_sz + frame_sz;
                }

                if (padding_size > payload_size) {
                    if(auto* connection = std::any_cast<Http2Connection>(&ctx.state_data))
                        connection->connection_invalid = true;
                    return preamble_sz + frame_sz;
                }
                payload_size -= padding_size;
                if(typ == 5 && payload_size < sizeof(uint32_t)) {
                    _err("Frame: padded PUSH_PROMISE has no promised stream id");
                    connection->connection_invalid = true;
                    return preamble_sz + frame_sz;
                }

                {
                    _inf("Frame: type = %s, flags = %d, size = %d, stream = %d, side = %c", frame_type_str(typ), flg, frame_sz,
                         stream_id, from_side(side));

                    if (typ == 1 && (flg & 0x20))
                        _inf("Frame prio: stream dep = %X, weight: %d", stream_dep, wgh);

                    _deb("Frame: \r\n%s", hex_dump(frame.view(0, frame_sz), 4, 0, true).c_str());

                    // A header block must be followed by CONTINUATION frames
                    // without any interleaved frame in the same direction.
                    if (typ != 9) {
                        if (auto* connection = std::any_cast<Http2Connection>(&ctx.state_data)) {
                            auto& pending = side == side_t::LEFT
                                            ? connection->request_headers_pending
                                            : connection->response_headers_pending;
                            if (pending.active()) {
                                _err("non-CONTINUATION frame received while header block is pending");
                                pending.clear();
                                connection->connection_invalid = true;
                                return preamble_sz + frame_sz;
                            }
                        }
                    }

                    if(frame_sz > 0 || typ == 0 || typ == 1 || typ == 9) {
                        if (typ == 0) {
                            auto& connection_window = side == side_t::LEFT
                                ? connection->client_connection_window
                                : connection->server_connection_window;
                            if(static_cast<std::int64_t>(frame_sz) > connection_window) {
                                _err("Frame: HTTP/2 DATA exceeds connection flow window");
                                connection->connection_invalid = true;
                                return preamble_sz + frame_sz;
                            }
                            connection_window -= frame_sz;

                            bool pushed_stream = false;
                            if(auto stream = connection->streams.find(stream_id);
                               stream != connection->streams.end()) {
                                auto& stream_window = side == side_t::LEFT
                                    ? stream->second.request_flow_window_
                                    : stream->second.response_flow_window_;
                                if(static_cast<std::int64_t>(frame_sz) > stream_window) {
                                    _err("Frame: HTTP/2 DATA exceeds stream flow window");
                                    if(side == side_t::LEFT)
                                        stream->second.request_invalid_ = true;
                                    else
                                        stream->second.response_invalid_ = true;
                                    return preamble_sz + frame_sz;
                                }
                                stream_window -= frame_sz;
                            } else if(side == side_t::RIGHT) {
                                auto promised = connection->promised_flow_windows.find(
                                    static_cast<uint32_t>(stream_id));
                                if(promised != connection->promised_flow_windows.end()) {
                                    pushed_stream = true;
                                    if(static_cast<std::int64_t>(frame_sz) > promised->second) {
                                        connection->promised_streams.erase(
                                            static_cast<uint32_t>(stream_id));
                                        connection->active_promised_streams.erase(
                                            static_cast<uint32_t>(stream_id));
                                        connection->promised_flow_windows.erase(promised);
                                        connection->refused_promised_streams.insert(
                                            static_cast<uint32_t>(stream_id));
                                        return preamble_sz + frame_sz;
                                    }
                                    promised->second -= frame_sz;
                                } else if(connection->promised_streams.count(
                                              static_cast<uint32_t>(stream_id)) != 0) {
                                    pushed_stream = true;
                                    connection->promised_streams.erase(
                                        static_cast<uint32_t>(stream_id));
                                    connection->refused_promised_streams.insert(
                                        static_cast<uint32_t>(stream_id));
                                    return preamble_sz + frame_sz;
                                }
                            }

                            buffer data;
                            if(payload_size != 0)
                                data = frame.view(payload_offset, payload_size);
                            const auto id = static_cast<uint32_t>(stream_id);
                            if(side == side_t::LEFT &&
                               connection->refused_client_streams.count(id) != 0) {
                                if((flg & 0x01U) != 0)
                                    connection->refused_client_streams.erase(id);
                            } else if(side == side_t::RIGHT &&
                                      connection->refused_promised_streams.count(id) != 0) {
                                if((flg & 0x01U) != 0)
                                    connection->refused_promised_streams.erase(id);
                            } else if(!pushed_stream)
                                process_data(ctx, side, stream_id, flg, data);
                            else if((flg & 0x01U) != 0) {
                                connection->promised_streams.erase(
                                    static_cast<uint32_t>(stream_id));
                                connection->active_promised_streams.erase(
                                    static_cast<uint32_t>(stream_id));
                                connection->promised_flow_windows.erase(
                                    static_cast<uint32_t>(stream_id));
                            }
                        } else if (typ == 1 || typ == 5 || typ == 9) {
                            auto data = frame.view(payload_offset, payload_size);
                            auto* connection = std::any_cast<Http2Connection>(&ctx.state_data);
                            if (!connection) {
                                ctx.state_data = std::make_any<Http2Connection>();
                                connection = std::any_cast<Http2Connection>(&ctx.state_data);
                            }
                            auto& pending = side == side_t::LEFT
                                            ? connection->request_headers_pending
                                            : connection->response_headers_pending;

                            if (typ == 1) {
                                bool pushed_response = side == side_t::RIGHT &&
                                    connection->promised_streams.count(
                                        static_cast<uint32_t>(stream_id)) != 0;
                                bool refused_pushed_response = side == side_t::RIGHT &&
                                    connection->refused_promised_streams.count(
                                        static_cast<uint32_t>(stream_id)) != 0;
                                if(pushed_response &&
                                   connection->active_promised_streams.count(
                                       static_cast<uint32_t>(stream_id)) == 0) {
                                    connection->active_promised_streams.insert(
                                        static_cast<uint32_t>(stream_id));
                                    connection->promised_flow_windows.emplace(
                                        static_cast<uint32_t>(stream_id),
                                        connection->server_initial_stream_window);
                                }
                                bool refused_request = side == side_t::LEFT &&
                                    connection->refused_client_streams.count(
                                        static_cast<uint32_t>(stream_id)) != 0;
                                if(side == side_t::LEFT &&
                                   connection->streams.count(stream_id) == 0 &&
                                   !refused_request) {
                                    const bool exceeds_goaway =
                                        connection->server_goaway_last_stream_id &&
                                        static_cast<uint32_t>(stream_id) >
                                            *connection->server_goaway_last_stream_id;
                                    if(exceeds_goaway) {
                                        if(connection->refused_client_streams.size() >=
                                           max_tracked_streams) {
                                            connection->connection_invalid = true;
                                            return preamble_sz + frame_sz;
                                        }
                                        connection->refused_client_streams.insert(
                                            static_cast<uint32_t>(stream_id));
                                        refused_request = true;
                                    }
                                }
                                if (flg & flag_end_headers) {
                                    if(pushed_response || refused_pushed_response) {
                                        synchronize_headers(ctx, side, data);
                                        if((flg & 0x01U) != 0) {
                                            const auto id = static_cast<uint32_t>(stream_id);
                                            connection->promised_streams.erase(id);
                                            connection->active_promised_streams.erase(id);
                                            connection->promised_flow_windows.erase(id);
                                            connection->refused_promised_streams.erase(id);
                                        }
                                    } else if(refused_request) {
                                        synchronize_headers(ctx, side, data);
                                        if((flg & 0x01U) != 0)
                                            connection->refused_client_streams.erase(
                                                static_cast<uint32_t>(stream_id));
                                    } else {
                                        process_headers(ctx, side, stream_id, flg, data);
                                    }
                                } else {
                                    pending.stream_id = stream_id;
                                    pending.initial_flags = flg;
                                    pending.decode_only = pushed_response ||
                                        refused_pushed_response || refused_request;
                                    pending.bytes.clear();
                                    if (data.size() > max_pending_header_block_size) {
                                        _err("initial HTTP/2 header fragment exceeds inspection limit");
                                        pending.clear();
                                        connection->connection_invalid = true;
                                    } else if (!data.empty()) {
                                        auto* begin = static_cast<unsigned char*>(data.data());
                                        pending.bytes.assign(begin, begin + data.size());
                                    }
                                }
                            } else if(typ == 5) {
                                const auto associated = connection->streams.find(stream_id);
                                const bool valid_push = side == side_t::RIGHT &&
                                    connection->server_push_enabled && stream_id != 0 &&
                                    payload_size >= 4 &&
                                    associated != connection->streams.end() &&
                                    !associated->second.response_ended_;
                                if(!valid_push) {
                                    _err("invalid HTTP/2 PUSH_PROMISE");
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                const auto promised_stream = ntohl(
                                    frame.get_at<uint32_t>(payload_offset)) & 0x7fffffffU;
                                if(promised_stream == 0 || (promised_stream & 1U) != 0 ||
                                   promised_stream <= connection->highest_promised_stream_id) {
                                    _err("invalid HTTP/2 promised stream id");
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                if(connection->promised_streams.size() +
                                       connection->refused_promised_streams.size() >=
                                   max_tracked_streams) {
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                connection->highest_promised_stream_id = promised_stream;
                                const bool exceeds_goaway =
                                    connection->client_goaway_last_stream_id &&
                                    promised_stream > *connection->client_goaway_last_stream_id;
                                if(exceeds_goaway)
                                    connection->refused_promised_streams.insert(promised_stream);
                                else
                                    connection->promised_streams.insert(promised_stream);
                                payload_offset += sizeof(uint32_t);
                                payload_size -= sizeof(uint32_t);
                                data.clear();
                                if(payload_size != 0)
                                    data = frame.view(payload_offset, payload_size);
                                if(flg & flag_end_headers) {
                                    if(data.empty() || !synchronize_headers_impl(
                                           ctx, side, data, true)) {
                                        connection->promised_streams.erase(promised_stream);
                                        connection->refused_promised_streams.insert(promised_stream);
                                        associated->second.response_invalid_ = true;
                                    }
                                } else {
                                    pending.stream_id = stream_id;
                                    pending.promised_stream_id = promised_stream;
                                    pending.initial_flags = 0;
                                    pending.decode_only = true;
                                    pending.bytes.clear();
                                    if(data.size() > max_pending_header_block_size) {
                                        pending.clear();
                                        connection->connection_invalid = true;
                                    } else if(!data.empty()) {
                                        auto* begin = static_cast<unsigned char*>(data.data());
                                        pending.bytes.assign(begin, begin + data.size());
                                    }
                                }
                            } else if (!pending.active() || pending.stream_id != stream_id) {
                                _err("unexpected CONTINUATION stream");
                                pending.clear();
                                connection->connection_invalid = true;
                                return preamble_sz + frame_sz;
                            } else {
                                if (data.size() > max_pending_header_block_size - pending.bytes.size()) {
                                    _err("continued HTTP/2 header block exceeds inspection limit");
                                    pending.clear();
                                    connection->connection_invalid = true;
                                    return preamble_sz + frame_sz;
                                }
                                if (!data.empty()) {
                                    auto* begin = static_cast<unsigned char*>(data.data());
                                    pending.bytes.insert(pending.bytes.end(), begin, begin + data.size());
                                }
                                if (flg & flag_end_headers) {
                                    buffer complete_headers;
                                    complete_headers.assign(pending.bytes.data(), pending.bytes.size());
                                    const auto complete_flags = static_cast<uint8_t>(
                                        pending.initial_flags | flag_end_headers);
                                    const bool decode_only = pending.decode_only;
                                    const auto promised_stream_id = pending.promised_stream_id;
                                    const bool retire_refused = decode_only &&
                                        side == side_t::LEFT &&
                                        (complete_flags & 0x01U) != 0 &&
                                        connection->refused_client_streams.count(
                                            static_cast<uint32_t>(stream_id)) != 0;
                                    pending.clear();
                                    if(decode_only) {
                                        if(promised_stream_id != 0) {
                                            if(!synchronize_headers_impl(ctx, side,
                                                   complete_headers, true)) {
                                                connection->promised_streams.erase(
                                                    promised_stream_id);
                                                connection->refused_promised_streams.insert(
                                                    promised_stream_id);
                                            }
                                        } else {
                                            synchronize_headers(ctx, side, complete_headers);
                                        }
                                    } else {
                                        process_headers(ctx, side, stream_id,
                                                        complete_flags, complete_headers);
                                    }
                                    if(retire_refused)
                                        connection->refused_client_streams.erase(
                                            static_cast<uint32_t>(stream_id));
                                }
                            }
                        } else if(typ == 6) {
                            auto data = frame.view(payload_offset, payload_size);
                            process_ping(ctx, side, stream_id, flg, data);
                        } else {
                            auto data = frame.view(payload_offset, payload_size);
                            process_other(ctx, side, stream_id, flg, data);
                        }
                    }
                    else {
                        _inf("Frame: zero size");
                    }
                }
                return  preamble_sz + frame_sz;
            }
            else {
                _deb("frame is incomplete (frame size: %d, data in buffer: %d", frame_sz, frame.size());
            }

            return 0;
        };


        size_t load_prev_state(EngineCtx& ctx, size_t abs_index) {
            auto const& log = log::http2_state;

            std::optional<state_data_t> prev_state;
            if(not ctx.origin) {
                _err("no ctx origin");
                return 0;
            }

            if(not ctx.state_data.has_value()) return 0;

            try {
                prev_state = std::any_cast<state_data_t>(ctx.state_info);
            } catch (std::bad_any_cast const& e) {
                _deb("state: no previous state %s", e.what());
            }

            if(prev_state) {
                if(prev_state->first != abs_index) {
                    _deb("state: invalid due flow change");
                } else {
                    _deb("state: valid data pointer found at %d", prev_state->second);
                    return prev_state->second;
                }
            }
            return 0L;
        }

        void save_state(EngineCtx& ctx, std::size_t abs_index, std::size_t processed) {
            auto const& log = log::http2_state;

            ctx.state_info = std::make_any<state_data_t>(abs_index, processed);
            _deb("state: saving processed bytes in this flow: %d", processed);
        }

        void start(EngineCtx& ctx) {

            // origin guard
            if(not ctx.origin) {
                return;
            }
            if (not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }

            auto const& log = log::http2;


            auto round = 0;
            auto pos_size = ctx.origin->flow().pos_size();
            auto q_size = ctx.origin->flow().flow_queue().size();
            if (q_size == 0) {
                _deb("start - no flow blocks available");
                return;
            }

            const size_t blocks_seen = ctx.flow_seen ? ctx.flow_seen->blocks_seen : 0;
            size_t to_see_back_sz = pos_size > blocks_seen ? pos_size - blocks_seen : 0;
            if(to_see_back_sz > q_size)
                to_see_back_sz = q_size; // we cannot see anything back

            _dia("start - engine checked new data - want check back %d blocks, queue size: %d, full flow size %d",
                            to_see_back_sz, q_size, pos_size);

            // we want to see at least one back!
            if(to_see_back_sz == 0) to_see_back_sz = 1;

            // ctx.flow_pos = ctx.origin->flow().flow_queue().size() - to_see_back_sz;
            auto flow_pos = q_size - to_see_back_sz; // start with index of last element, unless we have missed blocks

            // yes, label, bitches
            on_more_blocks:

            _dia("start - current block set to index %d", flow_pos);


            auto const& last_flow_entry = ctx.origin->flow().flow_queue().at(flow_pos);
            auto const& side = last_flow_entry.source();
            auto const& h2_buffer= last_flow_entry.data();
            auto const h2_buffer_sz = h2_buffer->size();

            auto abs_index = pos_size - q_size + flow_pos;

            if(ctx.new_data_check(abs_index + 1, h2_buffer_sz)) {
                ctx.update_seen_block(abs_index + 1, h2_buffer_sz);
            }
            else {
                _dia("start - engine checked no new data");
                return;
            }

            _dia("start round %d, flow index=%d len=%d, full_len=%d", round, flow_pos, ctx.origin->flow().size(), ctx.origin->flow().pos_size());
            _dia("flow path: %s", ctx.origin->flow().hr().c_str());

            std::size_t starting_index = load_prev_state(ctx, abs_index);
            if(starting_index >= h2_buffer_sz) {

                if(starting_index == h2_buffer_sz) {
                    _deb("there is nothing more to read!");
                }
                else {
                    _err("starting index in the future");
                }
                return;
            }

            std::size_t if_magic = 0L;
            auto starting_buffer = h2_buffer->view(starting_index);

            if(side == 'r') {
                if (ctx.status == EngineCtx::status_t::START) {
                    // eliminate finding magic later in the flow
                    if (flow_pos < 5 and h2_buffer_sz >= txt::magic_sz) {
                        if_magic = find_magic(starting_buffer);

                        // save starting position + size of magic
                        if (if_magic > 0) {
                            save_state(ctx, abs_index, starting_index + if_magic);
                            ctx.status = EngineCtx::status_t::MAGIC;

                            auto const* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
                            if(not state_data)
                                ctx.state_data = std::make_any<Http2Connection>();
                        }

                        if (if_magic + 4 > h2_buffer_sz) {
                            _err("not enough data to read");
                            return;
                        }
                    } else {
                        _deb("too late for magic lookup");
                        ctx.status = EngineCtx::status_t::MAGIC;
                    }
                }
            }

            buffer frame = starting_buffer.view(if_magic);
            std::size_t cur_off = 0L;
            std::size_t total = 0L;
            do {
                frame = frame.view(cur_off);

                try {
                    // convert side from signature read/write r/w meaning to left/right l/r
                    cur_off = process_frame(ctx, side == 'r' ? side_t::LEFT : side_t::RIGHT , frame);
                    if(cur_off == 0) {
                        // frame not complete
                        break;
                    }
                    total += cur_off;
                }
                catch(std::out_of_range const& e) {
                    _err("incomplete frame: last read size = %d", cur_off);
                    _err("incomplete frame: total read size = %d", total);
                    _err("incomplete frame: %s", e.what());
                    _war("data dump: \r\n%s", hex_dump(frame, 4, 'E', true).c_str());
                    break;
                }

                if(cur_off > frame.size()) {
                    _err("incomplete frame %d / %d", cur_off, frame.size());
                    break;
                }

            } while(total < starting_buffer.size() - if_magic);


            save_state(ctx, abs_index, starting_index + if_magic + total);

            if(flow_pos + 1 < ctx.origin->flow().flow_queue().size()) {
                // move to next pos if we are not finished and missed more arrived blocks
                // this usally happens if left and write sides both retrieved data at once
                flow_pos++;
                round++;
                _dia("moving to next flow block: index %d", flow_pos);

                goto on_more_blocks;
            }
        }
    }
}
