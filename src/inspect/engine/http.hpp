/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#ifndef HTTP1ENGINE_HPP
#define  HTTP1ENGINE_HPP

#include <regex>

#include <inspect/engine.hpp>

namespace sx::engine::http {

    constexpr const char* str_unknown = "???";
    constexpr const char* str_http1 = "http1";
    constexpr const char* str_http1_0 = "http1.0";
    constexpr const char* str_http1_1 = "http1.1";
    constexpr const char* str_http2 = "http2";

    struct ProtoRex {
        static std::regex const &http_req_get () {
            static std::regex r{R"((GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) *([^ \r\n\?]+)\??([^ \r\n]*))"};
            return r;
        };

        static std::regex const &http_req_ref () {
            static std::regex r{R"(Referer: *([^ \r\n]+))"};
            return r;
        };

        static std::regex const &http_req_host () {
            static std::regex r{R"(Host: *([^ \r\n]+))"};
            return r;
        };
    };

    struct app_HttpRequest : public ApplicationData {
        ~app_HttpRequest () override = default;

        struct HttpData {
            std::string host;
            std::string uri;
            std::string method;
            std::string params;
            std::string referer;
            std::string proto;
            std::string sub_proto;

            void clear() {
                host.clear();
                method.clear();
                uri.clear();
                params.clear();
                referer.clear();
                proto.clear();
            }
        } http_data;

        std::list<HttpData> http_history;
        constexpr static inline std::size_t http_history_max = 10000;
        void next() override {
            ApplicationData::next();

            http_history.push_back(http_data);
            http_data.clear();

            while(http_history.size() > http_history_max) {
                http_history.pop_front();
            }
        }


        enum class HTTP_VER { HTTP_1, HTTP1_0, HTTP1_1, HTTP2 } version;

        constexpr const char* http_str(HTTP_VER v) const {
            switch (v) {

                case HTTP_VER::HTTP_1:
                    return str_http1;
                case HTTP_VER::HTTP1_0:
                    return str_http1_0;
                case HTTP_VER::HTTP1_1:
                    return str_http1_1;
                case HTTP_VER::HTTP2:
                    return str_http2;
            }
            return str_unknown;
        }
        std::string protocol() const override {
            std::stringstream ss;
            ss << http_str(version);
            if(not http_data.sub_proto.empty()) {
                ss << "/" << http_data.sub_proto;
            }

            return ss.str();
        }

        // this function returns most usable link for visited site from the request.
        std::string original_request () override {
            if (!http_data.referer.empty()) {
                _deb("std::string original_request: using referer: %s", http_data.referer.c_str());
                return http_data.referer;
            }

            _deb("std::string original_request: using request: %s", request().c_str());
            return request();
        }

        std::string request () override {
            std::stringstream  ss;
            ss << http_data.proto << http_data.host << http_data.uri;
            if(not http_data.params.empty())
                ss << "?" << http_data.params;

            return ss.str();
        };

        std::vector<std::string> requests_all() override {
            std::vector<std::string> ret;
            auto cur = request();

            if(not cur.empty()) ret.push_back(cur);
            for (auto const& s: http_history) {
                auto a = app_HttpRequest();
                a.http_data = s;

                auto r = a.request();
                if(not r.empty()) ret.push_back(r);
            }
            return ret;
        }

        std::string to_string (int verbosity) const override {
            std::stringstream ret;

            ret << "AppData: ";
            if(auto up_str = ApplicationData::to_string(verbosity); not up_str.empty()) {
                ret << up_str << ": ";
            }
            ret << http_data.proto << http_data.host << http_data.uri << http_data.params;

            if (verbosity > INF) {

                if(not http_data.referer.empty()) ret << " via: " << http_data.referer;
                if(not http_data.method.empty()) ret << " meth: " << http_data.method;
                ret << " ver: " << http_str(version);
            }

            return ret.str();
        }

    TYPENAME_OVERRIDE("app_HttpRequest")

    private:
        logan_lite log {"com.app"};
    };


    namespace v1 {
        // request parsing
        void parse_request (EngineCtx &ctx, buffer const* buffer_data_string);
        bool find_referrer (EngineCtx &ctx, std::string_view data);
        bool find_host (EngineCtx &ctx, std::string_view data);
        bool find_method (EngineCtx &ctx, std::string_view data);

        // execute engine
        void start(EngineCtx &ctx);
    }

    namespace v2 {
        using state_data_t = std::pair<size_t, size_t>;

        struct txt {
            static constexpr const char* magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            static constexpr const size_t magic_sz = 24;
        };

        void start(EngineCtx &ctx);


        struct GunZip {
            buffer in;
        };


        struct Http2Stream {
            using value_list_t = std::map<std::string, std::vector<std::string>, std::less<>>;

            enum class content_type_t {
                PLAIN, GZIP
            };
            enum class sub_app_t {
                UNKNOWN, DNS
            };

            content_type_t content_encoding_{content_type_t::PLAIN};
            sub_app_t sub_app_{sub_app_t::UNKNOWN};
            value_list_t request_headers_;
            value_list_t response_headers_;
            std::optional<GunZip> gzip;

            std::string domain_;
            std::string hostname_;

            std::optional<std::string> request_header(std::string_view hdr) {
                return find_header(request_headers_, hdr);
            }

            std::optional<std::string> response_header(std::string_view hdr) {
                return find_header(response_headers_, hdr);
            }

            static std::optional<std::string> find_header(value_list_t const &where, std::string_view hdr) {
                if (auto const &it = where.find(hdr); it != where.end()) {
                    if (not it->second.empty()) {
                        auto const &hdr_val = it->second.back();
                        return std::make_optional<std::string>(hdr_val);
                    }
                }
                return std::nullopt;
            };

            std::optional<std::string> domain() {

                if (not domain_.empty()) return domain_;

                if (auto host = request_header(":authority"); host.has_value()) {

                    auto dns_split = string_split(host.value(), '.');
                    std::stringstream domain_ss;
                    int tld_counter = 0;
                    for (auto it = dns_split.rbegin(); it != dns_split.rend();) {

                        if (++tld_counter > 2) break;
                        domain_ss << *it;

                        ++it;
                        if (tld_counter > 0 and it != dns_split.rend())
                            domain_ss << ".";
                    }

                    domain_ = domain_ss.str();
                    hostname_ = host.value();

                    return domain_;
                }

                return std::nullopt;
            }

            std::optional<std::string> hostname() {
                if(domain()) {
                    return hostname_;
                }
                return  std::nullopt;
            }
        };

        struct Http2Connection {
            // map
            mp::map<long,Http2Stream> streams;
        };
    }

    struct log {
        static inline logan_lite http1 {"com.app.http1" };
        static inline logan_lite http2 {"com.app.http2" };
        static inline logan_lite http2_state {"com.app.http2.state" };
        static inline logan_lite http2_headers {"com.app.http2.headers" };
        static inline logan_lite http2_frames {"com.app.http2.frames" };
        static inline logan_lite http2_subapp {"com.app.http2.subapp" };
    };
}

#endif