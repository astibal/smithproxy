#include <sslcom.hpp>

#include <inspect/engine/http.hpp>
#include <proxy/mitmhost.hpp>

#ifdef USE_HPACK
#include <ext/hpack/hpack.hpp>
#endif

#include <inspect/dnsinspector.hpp>

namespace sx::engine::http {

    namespace v1 {

        void find_referrer (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            std::smatch m_ref;

            auto ix_ref = data.find("Referer: ");
            if (ix_ref != std::string::npos) {
                std::string ref_start ( data.substr(ix_ref, std::min(std::size_t(128), data.size() - ix_ref)) );
                if (std::regex_search(ref_start, m_ref, ProtoRex::http_req_ref())) {
                    std::string str_temp;

                    str_temp = m_ref[1].str();

                    if (not ctx.application_data) {
                        ctx.application_data = std::make_unique<app_HttpRequest>();
                    }

                    auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                    if (app_request != nullptr) {
                        app_request->referer = str_temp;
                        _deb("Referer: %s", ESC(app_request->referer));
                    }
                }
            }
        }

        void find_host (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            auto ix_host = data.find("Host: ");
            if (ix_host != std::string::npos) {

                std::string host_start( data.substr(ix_host, std::min(std::size_t(128), data.size() - ix_host)) );
                std::smatch m_host;

                if (std::regex_search(host_start, m_host, ProtoRex::http_req_host())) {
                    if (!m_host.empty()) {
                        auto str_temp = m_host[1].str();

                        if (not ctx.application_data) {
                            ctx.application_data = std::make_unique<app_HttpRequest>();
                        }

                        auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                        if (app_request != nullptr) {
                            app_request->host = str_temp;
                            _dia("Host: %s", app_request->host.c_str());


                            // NOTE: should be some config variable
                            bool check_inspect_dns_cache = true;
                            if (check_inspect_dns_cache) {

                                std::scoped_lock<std::recursive_mutex> d_(DNS::get().dns_lock());

                                auto dns_resp_a = DNS::get().dns_cache().get("A:" + app_request->host);
                                auto dns_resp_aaaa = DNS::get().dns_cache().get("AAAA:" + app_request->host);

                                if (dns_resp_a && ctx.origin->com()->l3_proto() == AF_INET) {
                                    _deb("HTTP inspection: Host header matches DNS: %s", ESC(dns_resp_a->question_str_0()));
                                } else if (dns_resp_aaaa && ctx.origin->com()->l3_proto() == AF_INET6) {
                                    _deb("HTTP inspection: Host header matches IPv6 DNS: %s",
                                         ESC(dns_resp_aaaa->question_str_0()));
                                } else {
                                    _war("HTTP inspection: 'Host' header value '%s' DOESN'T match DNS!",
                                         app_request->host.c_str());
                                }
                            }
                        }
                    }
                }
            }
        }

        void find_method (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            std::string method_start(data.substr(0, std::min(std::size_t(128), data.size())));
            std::smatch m_get;

            if (std::regex_search(method_start, m_get, ProtoRex::http_req_get())) {

                auto msize = m_get.size();

                if (msize > 1) {
                    if (not ctx.application_data) {
                        ctx.application_data = std::make_unique<app_HttpRequest>();
                    }
                    auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                    if(not app_request) {
                        _err("find_method: incorrect appdata object type");
                        return;
                    }

                    app_request->method = m_get[1].str();
                    _dia("method: %s", ESC(app_request->method));

                    if (msize > 2) {
                        app_request->version = app_HttpRequest::HTTP_VER::HTTP_1;
                        app_request->uri = m_get[2].str();
                        _dia("uri: %s", ESC(app_request->uri));
                    }

                    if (msize > 3) {
                        app_request->params = m_get[3].str();
                        _dia("params: %s", ESC(app_request->params));

                    }
                }
            }
        }

        void parse_request(EngineCtx &ctx, buffer const* buffer_data) {
            auto const& log = log::http1;

            auto data = buffer_data->string_view();

            find_method(ctx, data);
            find_host(ctx, data);
            find_referrer(ctx, data);


            auto engine_http1_set_proto = [&ctx,&log] () {
                auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());
                if (app_request != nullptr) {
                    // detect protocol (plain vs ssl)
                    auto const* proto_com = dynamic_cast<SSLCom *>(ctx.origin->com());
                    if (proto_com != nullptr) {
                        app_request->proto = "https://";
                        app_request->is_ssl = true;
                    } else {
                        app_request->proto = "http://";
                    }


                    _inf("http request: %s", ESC(app_request->str()));
                } else {
                    _err("http request: app_request failed");
                }
            };


            engine_http1_set_proto();

            ctx.origin->replacement_type(MitmHostCX::REPLACETYPE_HTTP);

        }

        void start (EngineCtx &ctx) {

            // origin guard
            if(not ctx.origin) {
                return;
            }

            auto const& log = log::http1;
            _deb("start: cx.meter_read %ldB, cx.meter_write %ldB", ctx.origin->meter_read_bytes, ctx.origin->meter_write_bytes);

            auto const& [ http_request1_side, http_request1_buffer ] = ctx.origin->flow().data().back();

            // limit this rather info/convenience regexing to 128 bytes

            // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
            // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
            // as there is nothing dependant on full URI and more can slow box down for not real benefit.


            if(http_request1_side == 'r') {
                _dia("start: flow block index %d, size %dB", ctx.flow_pos, http_request1_buffer->size());
                std::string buffer_data_string((const char *) http_request1_buffer->data(), http_request1_buffer->size());
                parse_request(ctx, http_request1_buffer.get());
            }

            _deb("start finished");
        }
    }

    namespace v2 {

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

        uint32_t find_frame_sz(buffer const& frame) {
            auto const& log = log::http2;

            std::size_t cur_off = 0;

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


        void detect_app(EngineCtx& ctx, side_t side, std::shared_ptr<app_HttpRequest> const& app_data,
                        long stream_id, uint8_t flags, buffer const& data) {

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
            if(state_data) {
                auto &stream_state = state_data->streams[stream_id];

                auto find_header_last_val = [&](std::string_view hdr) -> std::optional<std::string> {
                    if(auto const& it = stream_state.request_headers_.find(hdr); it != stream_state.request_headers_.end()) {
                        if(not it->second.empty()) {
                            auto const& hdr_val = it->second.back();
                            return std::make_optional<std::string>(hdr_val);
                        }
                    }
                    return std::nullopt;
                };

                if(side == side_t::LEFT) {
                    if(auto path = find_header_last_val(":path"); path and path.value() == "/dns-query") {
                        stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                    }
                    // now look in properties!
//                    else if(auto const& val = app_data->properties["content-type"] ; not val.empty()) {
//                        if(val == "application/dns-message")
//                            stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
//                    }
                    else if(auto const& val = app_data->properties["accept"] ; not val.empty()) {
                        if(val == "application/dns-message")
                            stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                    }
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
                            app_data->host.clear();
                            app_data->method.clear();
                            app_data->uri.clear();
                            app_data->params.clear();
                            app_data->referer.clear();
                            app_data->proto.clear();

                            app_data->host = hdr_elem;
                        }
                    } else if (hdr == ":scheme") {
                        if (app_data) app_data->proto = hdr_elem + "://";
                    } else if (hdr == ":path") {
                        if (app_data) app_data->uri = hdr_elem;
                    } else if (hdr == ":method") {
                        if (app_data) app_data->method = hdr_elem;
                    }

                    // save all left (request) values
                    app_data->properties[hdr] = hdr_elem;

                }
                else {
                    if(hdr == "content-encoding") {
                        if(hdr_elem == "gzip") stream_state.content_encoding_ = Http2Stream::content_type_t::GZIP;
                    }
                }
                touch_header(hdr.c_str());
            }
        }

        void process_headers(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {

#ifdef USE_HPACK
            auto const& log = log::http2_headers;

            HPACK::decoder_t dec;
            auto data_string = std::string((const char*)data.data(), data.size());
            auto vec = std::vector<uint8_t>(data_string.begin(), data_string.end());

            if(not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }
            auto my_app_data = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
            if(my_app_data) my_app_data->version = app_HttpRequest::HTTP_VER::HTTP2;

            if (dec.decode(vec)) {
                for (auto& [ hdr, vlist ] : dec.headers()) {
                    for(auto const& hdr_elem: vlist) {
                        process_header_entry(ctx, side, my_app_data,
                                             stream_id, flags, data, hdr, hdr_elem);
                    }
                }
                detect_app(ctx, side, my_app_data, stream_id, flags, data);

            } else {
                _err("Frame: hpack decode error");
            }
#endif
        }

        void process_data(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
//            auto const &log = log::http2;

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
            if(state_data) {
                auto& stream_state = state_data->streams[stream_id];

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
                            auto const &log = log::http2_subapp;

                            std::string content_type;
                            // get content-type from stream response headers and fallback to 'accept' value
                            if(stream_state.response_headers_.find("content-type") != stream_state.response_headers_.end()) {
                                content_type = stream_state.response_headers_["content-type"].back();
                            }
                            if(content_type.empty())
                                content_type = ctx.application_data->properties["accept"];

                            _dia("subapp detected: DoH+%s", content_type.c_str());
                            _deb("DNS response bytes: \r\n%s", hex_dump(data, 4, 0, true).c_str());


                            if(content_type == "application/dns-message") {

                                // acknowledge next 5kB as expected continuous flow data
                                ctx.origin->acknowledge_continuous_mode(5000);

                                auto resp = std::make_shared<DNS_Response>();

                                if (auto parsed_bytes = resp->load(&data); parsed_bytes) {
                                    _dia("DNS response: %s", resp->to_string(iINF).c_str());

                                    DNS_Inspector::store(resp);
                                }
                            }
                            else {
                                _err("DNS response: unknown content type");
                            }
                        }
                        break;


                    case Http2Stream::sub_app_t::UNKNOWN:
                    default:
                        ;
                }
            }
        }


        void process_other(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
        }

        std::size_t process_frame(EngineCtx& ctx, side_t side, buffer& frame) {
            auto const& log = log::http2_frames;

            auto frame_sz = find_frame_sz(frame);
            std::size_t cur_off = 3L;
            size_t add_hdr = 0;

            constexpr size_t preamble_sz = 9L;

            if (frame_sz <= frame.size()) {
                auto typ = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);

                auto flg = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);
                auto stream_id = (long) ntohl(frame.get_at<uint32_t>(cur_off)); cur_off += sizeof(uint32_t);

                // end of preamble

                uint32_t stream_dep = 0L;
                uint8_t wgh = 0;

                if(flg & 0x20) {
                    stream_dep = frame.get_at<uint32_t>(cur_off); cur_off += sizeof(uint32_t);
                    wgh = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);

                    add_hdr += 5;
                }

                {
                    _inf("Frame: type = %s, flags = %d, size = %d, stream = %d", frame_type_str(typ), flg, frame_sz,
                         stream_id);

                    if (flg & 0x20)
                        _inf("Frame prio: stream dep = %X, weight: %d", stream_dep, wgh);

                    _deb("Frame: \r\n%s", hex_dump(frame, 4, 0, true).c_str());

                    if(typ == 0) {
                        auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
                        process_data(ctx, side, stream_id, flg, data);
                    }
                    else if(typ == 1) {
                        auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
                        process_headers(ctx, side, stream_id, flg, data);
                    }
                    else {
                        auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
                        process_other(ctx, side, stream_id, flg, data);
                    }


                }
            }


            return  preamble_sz + frame_sz;
        };


        size_t load_prev_state(EngineCtx& ctx) {
            auto const& log = log::http2_state;

            std::optional<state_data_t> prev_state;
            if(not ctx.origin) {
                _err("no ctx origin");
                return 0;
            }

            try {
                prev_state = std::any_cast<state_data_t>(ctx.state_info);
            } catch (std::bad_any_cast const& e) {
                _deb("state: no previous state %s", e.what());
            }

            if(prev_state) {
                if(prev_state->first != ctx.origin->flow().size()) {
                    _deb("state: invalid due flow change");
                } else {
                    _deb("state: valid data pointer found at %d", prev_state->second);
                    return prev_state->second;
                }
            }
            return 0L;
        }

        void save_state(EngineCtx& ctx, std::size_t processed) {
            auto const& log = log::http2_state;

            ctx.state_info = std::make_any<state_data_t>(ctx.origin->flow().size(), processed);
            _deb("state: saving processed bytes in this flow: %d", processed);
        }

        void start(EngineCtx& ctx) {

            // origin guard
            if(not ctx.origin) {
                return;
            }

            auto const& log = log::http2;
            auto const& [ side, h2_buffer ] = ctx.origin->flow().data().back();

            _dia("start at flow #%d", ctx.origin->flow().size());
            _dia("flow path: %s", ctx.origin->flow().hr().c_str());

            std::size_t starting_index = load_prev_state(ctx);
            if(starting_index >= h2_buffer->size()) {

                if(starting_index == h2_buffer->size()) {
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
                    if (ctx.flow_pos < 5 and h2_buffer->size() >= txt::magic_sz) {
                        if_magic = find_magic(starting_buffer);

                        // save starting position + size of magic
                        if (if_magic > 0) {
                            save_state(ctx, starting_index + if_magic);
                            ctx.status = EngineCtx::status_t::MAGIC;

                            auto const* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
                            if(not state_data)
                                ctx.state_data = std::make_any<Http2Connection>();
                        }

                        if (if_magic + 4 > h2_buffer->size()) {
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
                    total += cur_off;
                }
                catch(std::out_of_range const& e) {
                    _err("incomplete frame: last read size = %d", cur_off);
                    _err("incomplete frame: total read size = %d", total);
                    _err("incomplete frame: %s", e.what());
                    _war("data dump: \r\n%s", hex_dump(frame, 4, 'E', true).c_str());
                    break;
                }

                if(cur_off == 0) {
                    _err("frame size zero");
                    break;
                }
                if(cur_off > frame.size()) {
                    _err("incomplete frame %d / %d", cur_off, frame.size());
                    break;
                }

            } while(total < starting_buffer.size() - if_magic);


            save_state(ctx, starting_index + if_magic + total);
        }
    }
}
