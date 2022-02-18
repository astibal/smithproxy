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
    constexpr const char* str_http1 = "http/1.x";
    constexpr const char* str_http1_0 = "http/1.0";
    constexpr const char* str_http1_1 = "http/1.1";
    constexpr const char* str_http2 = "http/2";


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

        std::string host;
        std::string uri;
        std::string method;
        std::string params;
        std::string referer;
        std::string proto;

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

        // this function returns most usable link for visited site from the request.
        std::string original_request () override {
            if (!referer.empty()) {
                _deb("std::string original_request: using referer: %s", referer.c_str());
                return referer;
            }

            _deb("std::string original_request: using request: %s", request().c_str());
            return request();
        }

        std::string request () override {

            if (uri == "/favicon.ico") {
                _deb("std::string original_request: avoiding favicon.ico");
                return host;
            }
            return proto + host + uri + params;
        };

        std::string to_string (int verbosity) const override {
            std::stringstream ret;

            ret << "AppData: " << proto << host << uri << params;

            if (verbosity > INF) {

                if(not referer.empty()) ret << " via: " << referer;
                if(not method.empty()) ret << " meth: " << method;
                ret << " ver: " << http_str(version);
            }

            return ret.str();
        }

    TYPENAME_OVERRIDE("app_HttpRequest")

    private:
        logan_lite log {"com.app"};
    };


    // request parsing
    void engine_http1_parse_request(EngineCtx &ctx, std::string const &data);
    void engine_http1_start_find_referrer (EngineCtx &ctx, std::string const &data);
    void engine_http1_start_find_host (EngineCtx &ctx, std::string const &data);
    void engine_http1_start_find_method (EngineCtx &ctx, std::string const &data);

    // execute engine
    void engine_http1_start (EngineCtx &ctx);

    struct log {
        static inline logan_lite http1 {"com.app.engine.http1" };
    };
}

#endif