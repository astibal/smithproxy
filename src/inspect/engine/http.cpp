#include <sslcom.hpp>

#include <inspect/engine/http.hpp>
#include <proxy/mitmhost.hpp>

#ifdef USE_HPACK
#include <ext/hpack/hpack.hpp>
#endif

namespace sx::engine::http {

    namespace v1 {

        void find_referrer (EngineCtx &ctx, std::string const &data) {
            auto const& log = log::http1;

            std::smatch m_ref;

            auto ix_ref = data.find("Referer: ");
            if (ix_ref != std::string::npos) {
                auto ref_start = data.substr(ix_ref, std::min(std::size_t(128), data.size() - ix_ref));
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

        void find_host (EngineCtx &ctx, std::string const &data) {
            auto const& log = log::http1;

            auto ix_host = data.find("Host: ");
            if (ix_host != std::string::npos) {

                auto host_start = data.substr(ix_host, std::min(std::size_t(128), data.size() - ix_host));
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

        void find_method (EngineCtx &ctx, std::string const &data) {
            auto const& log = log::http1;

            auto method_start = data.substr(0, std::min(std::size_t(128), data.size()));
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

        void parse_request(EngineCtx &ctx, std::string const &buffer_data_string) {
            auto const& log = log::http1;

            find_method(ctx, buffer_data_string);
            find_host(ctx, buffer_data_string);
            find_referrer(ctx, buffer_data_string);


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
            _deb("start");

            auto const& [ http_request1_side, http_request1_buffer ] = ctx.origin->flow().flow()[ctx.flow_pos];

            // limit this rather info/convenience regexing to 128 bytes

            // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
            // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
            // as there is nothing dependant on full URI and more can slow box down for not real benefit.


            if(http_request1_side == 'r') {
                _dia("start: flow block index %d, size %dB", ctx.flow_pos, http_request1_buffer->size());
                std::string buffer_data_string((const char *) http_request1_buffer->data(), http_request1_buffer->size());
                parse_request(ctx, buffer_data_string);
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

        std::size_t process_frame(buffer& frame) {
            auto const& log = log::http2;

            auto frame_sz = find_frame_sz(frame);
            std::size_t cur_off = 3L;

            if (frame_sz <= frame.size()) {
                auto typ = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);

                auto flg = frame.get_at<uint8_t>(cur_off);   cur_off += sizeof(uint8_t);
                auto sid = (long) ntohl(frame.get_at<uint32_t>(cur_off));   cur_off += sizeof(uint32_t);

                {
                    _inf("Frame: type = %s, flags = %d, size = %d, stream = %d", frame_type_str(typ), flg, frame_sz, sid);

                    if(typ == 0) {
                        auto const& log = log::http2_frames;
                        auto deb_view = frame.view(0, cur_off + frame_sz);

                        _dia("Data frame: \r\n%s", hex_dump(deb_view, 4, 0, true).c_str());
                    }
                    if(typ != 0) {
                        auto const& log = log::http2_frames;
                        auto deb_view = frame.view(0, cur_off + frame_sz);

                        _deb("Frame: \r\n%s", hex_dump(deb_view, 4, 0, true).c_str());
                    }


                    if(typ == 1) {
                        auto const& log = log::http2_headers;

#ifdef USE_HPACK
                        // skip frame headers, start of data
                        auto data = frame.view(9, frame_sz);

                        HPACK::decoder_t dec;
                        auto data_string = std::string((const char*)data.data(), data.size());
                        auto vec = std::vector<uint8_t>(data_string.begin(), data_string.end());

                        if (dec.decode(vec)) {
                            for (auto& hdr : dec.headers()) {
                                auto h = hdr.first;
                                auto v = hdr.second;
                                _inf("Frame: header/%s : %s", h.c_str(), v.c_str());
                            }
                        } else {
                            _err("Frame: hpack decode error");
                        }
#else
                        auto deb_view = frame.view(0, cur_off + frame_sz);
                        _dia("Headers frame: \r\n%s", hex_dump(deb_view, 4, 0, true).c_str());
#endif
                    }
                }

                // if(typ == 3) frame_sz = 24;
            }


            return cur_off + frame_sz;
        };


        size_t load_prev_state(EngineCtx& ctx) {
            auto const& log = log::http2_state;

            std::optional<state_data_t> prev_state;
            if(not ctx.origin) {
                _err("no ctx origin");
                return 0;
            }

            try {
                prev_state = std::any_cast<state_data_t>(ctx.data);
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

            ctx.data = std::make_any<state_data_t>(ctx.origin->flow().size(), processed);
            _deb("state: saving processed bytes in this flow: %d", processed);
        }

        void start(EngineCtx& ctx) {

            // origin guard
            if(not ctx.origin) {
                return;
            }

            auto const& log = log::http2;
            auto const& [ side, h2_buffer ] = ctx.origin->flow().flow().back();

            _dia("start at flow #%d", ctx.origin->flow().size());
            _dia("flow path: %s", ctx.origin->flow().hr().c_str());

            std::size_t starting_index = load_prev_state(ctx);
            if(starting_index >= h2_buffer->size()) {
                _deb("there is nothing more to read!");
                return;
            }


            std::size_t if_magic = 0L;
            auto starting_buffer = h2_buffer->view(starting_index);

            // eliminate finding magic later in the flow
            if(ctx.flow_pos < 5 and side == 'r' and h2_buffer->size() >= txt::magic_sz) {
                if_magic = find_magic(starting_buffer);
                if (if_magic + 4 > h2_buffer->size()) {
                    _err("not enough data to read");
                    return;
                }
            } else {
                _deb("too late for magic lookup");
            }

            buffer frame = starting_buffer.view(if_magic);
            std::size_t cur_off = 0L;
            std::size_t total = 0L;
            do {
                frame = frame.view(cur_off);

                try {
                    cur_off = process_frame(frame);
                }
                catch(std::out_of_range const& e) {
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

                total += cur_off;
            } while(total < starting_buffer.size() - if_magic);


            save_state(ctx, starting_index + if_magic + total);
        }
    }
}
