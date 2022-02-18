#include <sslcom.hpp>

#include <inspect/http1engine.hpp>
#include <proxy/mitmhost.hpp>

namespace sx::engine::http {

    void engine_http1_start_find_referrer (EngineCtx &ctx, std::string const &data) {
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

    void engine_http1_start_find_host (EngineCtx &ctx, std::string const &data) {
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

    void engine_http1_start_find_method (EngineCtx &ctx, std::string const &data) {
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
                    _err("engine_http1_start_find_method: incorrect appdata object type");
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

    void engine_http1_parse_request(EngineCtx &ctx, std::string const &buffer_data_string) {
        auto const& log = log::http1;

        engine_http1_start_find_method(ctx, buffer_data_string);
        engine_http1_start_find_host(ctx, buffer_data_string);
        engine_http1_start_find_referrer(ctx, buffer_data_string);


        auto engine_http1_set_proto = [&ctx] () {
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

    void engine_http1_start (EngineCtx &ctx) {

        // origin guard
        if(not ctx.origin) {
            return;
        }

        auto const& log = log::http1;
        _deb("engine_http1_start");

        auto const& [ http_request1_side, http_request1_buffer ] = ctx.origin->flow().flow()[ctx.flow_pos];

        // limit this rather info/convenience regexing to 128 bytes

        // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
        // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
        // as there is nothing dependant on full URI and more can slow box down for not real benefit.


        if(http_request1_side == 'r') {
            _dia("engine_http1_start: flow block index %d, size %dB", ctx.flow_pos, http_request1_buffer->size());
            std::string buffer_data_string((const char *) http_request1_buffer->data(), http_request1_buffer->size());
            engine_http1_parse_request(ctx, buffer_data_string);
        }

        _deb("engine_http1_start finished");
    }
}