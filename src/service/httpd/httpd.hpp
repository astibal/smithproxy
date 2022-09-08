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

#ifndef HTTPD_HPP_
#define HTTPD_HPP_

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <ext/json/json.hpp>
#include <main.hpp>

namespace sx::webserver {

using named_var_t = std::unordered_map<std::string, std::string>;
using sessions_t = std::unordered_map<std::string, named_var_t>;

struct HttpSessions {

    static inline std::mutex lock;
    static inline std::set<std::string> api_keys;
    static inline sessions_t access_keys;

    constexpr static const char* ATT_AUTH_TOKEN = "auth_token";
    constexpr static const char* ATT_CSRF_TOKEN = "csrf_token";

    static std::string table_value(std::string const& key, std::string const& varname, bool create=false) {
        auto lc_ = std::scoped_lock(lock);

        auto key_it = access_keys.find(key);
        if(create and key_it == access_keys.end()) {
            access_keys[key] = named_var_t(); key_it = access_keys.find(key);
        }

        if(key_it != access_keys.end()) {
            if(auto var_it = key_it->second.find(varname); var_it != key_it->second.end()) {
                return var_it->second;
            }
            else if(create) {
                return key_it->second[varname];
            }
        }

        return {};
    }

    static std::string generate_auth_token() {
        return "__AUTH_TOKEN__";
    }

    static std::string generate_csrf_token() {
        return "__CSRF_TOKEN__";
    }

    static bool validate_tokens(std::string const& auth_token, std::string const& csrf_token) {
        auto db_csrf_token = table_value(auth_token, "csrf_token");
        return csrf_token == db_csrf_token;
    }
};

std::thread* create_httpd_thread(unsigned short port);

struct HttpService_JsonResponseParams : public lmh::ResponseParams {
    nlohmann::json response;
};

class HttpService_JsonResponder : public lmh::DynamicController {
    std::string meth;
    std::string path;
    using responder_t  = std::function<HttpService_JsonResponseParams(struct MHD_Connection*,std::string const& requ)>;

    responder_t responder;

    static inline const std::vector<std::pair<std::string, std::string>> json_response_headers  = {
            { "X-Vendor", "smithproxy " SMITH_VERSION },
            { "Content-Type", "application/json" },
            { "Access-Control-Allow-Origin", "*" },
            };

public:
    HttpService_JsonResponder(std::string m, std::string p, responder_t r)
            : meth(std::move(m)), path(std::move(p)), responder(std::move(r)) {};

    bool validPath(const char* arg_path, const char* arg_method) override {
        if(arg_path == path and arg_method == meth) return true;

        if(arg_method == meth) {
            std::string argp = arg_path;
            if(argp.find(path + "?") == 0) {
                return true;
            }
        }
        return false;
    }

    lmh::ResponseParams createResponse(struct MHD_Connection * connection,
            const char * url, const char * method, const char * upload_data,
            size_t * upload_data_size, void** ptr, std::stringstream& response) override {

        auto meth_str = std::string(meth);
        std::string request_data;

        auto* body = static_cast<lmh::ConnectionState*>(*ptr);

        if (not body) {
            if(meth_str == "POST") {
                lmh::ResponseParams ret;
                ret.response_code = MHD_YES;
                if(not *ptr) *ptr = new lmh::ConnectionState(*this);

                return ret;
            }
        }
        else if(*upload_data_size > 0) {
            std::string inc(upload_data, *upload_data_size);
            body->request_data += inc.c_str();
            *upload_data_size = 0;

            request_data = body->request_data;
        }


        auto ret = responder(connection, request_data);

        if(ret.response_code == MHD_HTTP_OK) {

            ret.headers = json_response_headers;

            response << to_string(ret.response);
        }
        return ret;
    }

};


class HttpService_Status_Ping : public lmh::DynamicController {
public:
    bool validPath(const char* path, const char* method) override {
        const std::string this_path = "/api/status/ping";
        const std::string this_meth = "POST";

        return (this_path == path and this_meth == method);
    }

     lmh::ResponseParams createResponse(struct MHD_Connection * connection,
            const char * url, const char * method, const char * upload_data,
            size_t * upload_data_size, void** ptr, std::stringstream& response) override {

        lmh::ResponseParams ret;

        time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;

        nlohmann::json js = { { "version", SMITH_VERSION }, { "status", "ok" },
                              { "uptime", uptime },
                              { "uptime_str", uptime_string(uptime) } };
        response << to_string(js);

        return ret;
    }

};

}
#endif //HTTPD_HPP_