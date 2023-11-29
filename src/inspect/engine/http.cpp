#include <sslcom.hpp>

#include <inspect/engine/http.hpp>
#include <proxy/mitmhost.hpp>

#ifdef USE_HPACK
#include <ext/hpack/hpack.hpp>
#endif

#include <inspect/dnsinspector.hpp>
#include <inspect/kb/kb.hpp>

namespace sx::engine::http {

    namespace v1 {

        bool find_referrer (EngineCtx &ctx, std::string_view data) {
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
                        app_request->http_data.referer = str_temp;
                        _deb("Referer: %s", ESC(app_request->http_data.referer));
                    }

                    return true;
                }
            }

            return false;
        }

        bool find_host (EngineCtx &ctx, std::string_view data) {
            auto const& log = log::http1;

            auto ix_host = data.find("Host: ");

            // no point to continue
            if(ix_host == std::string::npos) return false;

            std::string host_start( data.substr(ix_host, std::min(std::size_t(128), data.size() - ix_host)) );

            std::smatch m_host;
            auto const regex_ret = std::regex_search(host_start, m_host, ProtoRex::http_req_host());
            if (regex_ret and not m_host.empty()) {

                auto str_temp = m_host[1].str();

                if (not ctx.application_data) {
                    ctx.application_data = std::make_unique<app_HttpRequest>();
                }

                if (auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get()); app_request) {
                    app_request->http_data.host = str_temp;
                    _dia("Host: %s", app_request->http_data.host.c_str());


                    // NOTE: should be some config variable
                    bool check_inspect_dns_cache = true;
                    if (check_inspect_dns_cache) {

                        std::string dns_resp;
                        auto proto = ctx.origin->com()->l3_proto();
                        const std::string prefix = (proto == AF_INET6 ? "AAAA:" : "A:");

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
                }

                return true;
            }

            return false;
        }

        bool find_method (EngineCtx &ctx, std::string_view data) {
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
                        return false;
                    }

                    app_request->http_data.method = m_get[1].str();
                    _dia("method: %s", ESC(app_request->http_data.method));

                    if (msize > 2) {
                        app_request->version = app_HttpRequest::HTTP_VER::HTTP_1;
                        app_request->http_data.uri = m_get[2].str();
                        _dia("uri: %s", ESC(app_request->http_data.uri));
                    }

                    if (msize > 3) {
                        app_request->http_data.params = m_get[3].str();
                        _dia("params: %s", ESC(app_request->http_data.params));

                    }
                }

                return true;
            }
            return false;
        }

        void parse_request(EngineCtx &ctx, buffer const* buffer_data) {
            auto const& log = log::http1;

            auto data = buffer_data->string_view();

            bool const have_method = find_method(ctx, data);
            bool const have_host = find_host(ctx, data);
            bool const have_referer = find_referrer(ctx, data);


            auto *app_request = dynamic_cast<app_HttpRequest *>(ctx.application_data.get());

            auto engine_http1_set_proto = [&ctx,&app_request] () {

                if (app_request != nullptr) {
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


            if(have_method) {
                engine_http1_set_proto();
                ctx.origin->replacement_type(MitmHostCX::REPLACETYPE_HTTP);

                if(not have_host) _not("http1: 'Host:' not found");
                if(not have_referer) _deb("http1: 'Referer:' not found");

                if(app_request) {
                    app_request->mark_populated();
                }
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
            ctx.flow_pos = ctx.origin->flow().flow_queue().size() - 1;

            // limit this rather info/convenience regexing to 128 bytes

            // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
            // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
            // as there is nothing dependent on full URI and more can slow box down for not real benefit.

            if(side == 'r') {

                auto const buf_sz = buffer->size();
                _dia("start: flow block index %d, size %dB", ctx.flow_pos, buf_sz);
                if(ctx.new_data_check(buf_sz)) {
                    ctx.update_seen_block(buf_sz);
                    parse_request(ctx, buffer);
                }
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


                if (auto path = stream_state.request_header(":path"); hostname.has_value()) {
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

            auto* state_data = std::any_cast<Http2Connection>(& ctx.state_data);
            if(state_data) {
                auto &stream_state = state_data->streams[stream_id];

                if(side == side_t::LEFT) {

                    if(auto path = stream_state.request_header(":path"); path and path.value() == "/dns-query") {
                        stream_state.sub_app_ = Http2Stream::sub_app_t::DNS;
                    }
                    else if(auto const& val = app_data->properties()["accept"] ; not val.empty()) {
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

        void process_headers(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {

#ifdef USE_HPACK
            if(data.empty()) return;

            auto const& log = log::http2_headers;

            HPACK::decoder_t dec;
            auto data_string = std::string((const char*)data.data(), data.size());
            auto vec = std::vector<uint8_t>(data_string.begin(), data_string.end());

            if(not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }
            auto my_app_data = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
            if(my_app_data) my_app_data->version = app_HttpRequest::HTTP_VER::HTTP2;

            try {
                if (not dec.decode(vec)) {
                    _err("Frame: hpack decode error");
                }
            } catch (std::invalid_argument const& e) {
                _err("Frame: hpack decode exception: %s", e.what());
            }

            for (auto& [ hdr, vlist ] : dec.headers()) {
                for(auto const& hdr_elem: vlist) {
                    process_header_entry(ctx, side, my_app_data,
                                         stream_id, flags, data, hdr, hdr_elem);
                }
            }
            detect_app(ctx, side, my_app_data, stream_id, flags, data);
            if(ctx.origin->opt_kb_enabled) {
                fill_kb(ctx, side, my_app_data, stream_id, flags, data);
            }
#endif
        }

        void process_data(EngineCtx& ctx, side_t side, long stream_id, uint8_t flags, buffer const& data) {
//            auto const &log = log::http2;

            if(data.empty()) return;

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
                                content_type = ctx.application_data->properties()["accept"];

                            _dia("subapp detected: DoH+%s", content_type.c_str());
                            _deb("DNS response bytes: \r\n%s", hex_dump(data, 4, 0, true).c_str());


                            if(content_type == "application/dns-message") {

                                // acknowledge next 5kB as expected continuous flow data
                                ctx.origin->acknowledge_continuous_mode(5000);

                                auto resp = std::make_shared<DNS_Response>();

                                if (auto parsed_bytes = resp->load(&data); parsed_bytes) {
                                    _dia("DNS response: %s", resp->to_string(iINF).c_str());

                                    DNS_Inspector::store(resp);

                                    if(auto httpa = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data); httpa) {
                                        httpa->http_data.sub_proto = "dns";
                                    }

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
            if(data.empty()) return;
        }

        std::size_t process_frame(EngineCtx& ctx, side_t side, buffer& frame) {
            constexpr size_t preamble_sz = 9L;
            if(frame.size() < preamble_sz) return 0L;

            auto const& log = log::http2_frames;

            auto frame_sz_opt = find_frame_sz(frame);

            // not possible to parse frame header
            if(not frame_sz_opt) return 0L;
            auto frame_sz = frame_sz_opt.value();

            std::size_t cur_off = 3L;
            size_t add_hdr = 0;

            if (frame_sz + preamble_sz <= frame.size()) {
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

                    if(frame_sz > 0) {
                        if (typ == 0) {
                            auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
                            process_data(ctx, side, stream_id, flg, data);
                        } else if (typ == 1) {
                            auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
                            process_headers(ctx, side, stream_id, flg, data);
                        } else {
                            auto data = frame.view(preamble_sz + add_hdr, frame_sz - add_hdr);
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


        size_t load_prev_state(EngineCtx& ctx) {
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
            if (not ctx.application_data) {
                ctx.application_data = std::make_unique<app_HttpRequest>();
            }

            auto const& log = log::http2;
            auto const& last_flow_entry = ctx.origin->flow().flow_queue().back();
            auto const& side = last_flow_entry.source();
            auto const& h2_buffer= last_flow_entry.data();
            auto const h2_buffer_sz = h2_buffer->size();

            ctx.flow_pos = ctx.origin->flow().flow_queue().size() - 1;

            if(ctx.new_data_check(h2_buffer_sz)) {
                ctx.update_seen_block(h2_buffer_sz);
            }
            else {
                _dia("start - engine checked no new data");
                return;
            }

            _dia("start at flow #%d", ctx.origin->flow().size());
            _dia("flow path: %s", ctx.origin->flow().hr().c_str());

            std::size_t starting_index = load_prev_state(ctx);
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
                    if (ctx.flow_pos < 5 and h2_buffer_sz >= txt::magic_sz) {
                        if_magic = find_magic(starting_buffer);

                        // save starting position + size of magic
                        if (if_magic > 0) {
                            save_state(ctx, starting_index + if_magic);
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


            save_state(ctx, starting_index + if_magic + total);
        }
    }
}
