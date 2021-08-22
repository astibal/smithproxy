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

std::thread* create_httpd_thread(unsigned short port);

struct HttpService_JsonResponseParams : public lmh::ResponseParams {
    nlohmann::json response;
};

class HttpService_JsonResponder : public lmh::DynamicController {
    std::string meth;
    std::string path;
    std::function<HttpService_JsonResponseParams(struct MHD_Connection*)> responder;

public:
    HttpService_JsonResponder(std::string m, std::string p, std::function<HttpService_JsonResponseParams(struct MHD_Connection*)> r)
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
            size_t * upload_data_size, std::stringstream& response) override {

        auto to_add = responder(connection);
        lmh::ResponseParams ret = static_cast<lmh::ResponseParams>(to_add);

        ret.headers.emplace_back("X-Vendor", string_format("Smithproxy-%s", SMITH_VERSION));
        ret.headers.emplace_back("Content-Type", "application/json");
        ret.headers.emplace_back("Access-Control-Allow-Origin", "*");

        response << to_string(to_add.response);
        return ret;
    }

};


class HttpService_Status_Ping : public lmh::DynamicController {
public:
    bool validPath(const char* path, const char* method) override {
        const std::string this_path = "/api/status/ping";
        const std::string this_meth = "GET";

        return (this_path == path and this_meth == method);
    }

     lmh::ResponseParams createResponse(struct MHD_Connection * connection,
            const char * url, const char * method, const char * upload_data,
            size_t * upload_data_size, std::stringstream& response) override {

        lmh::ResponseParams ret;
        ret.headers.emplace_back("X-Vendor", string_format("Smithproxy-%s", SMITH_VERSION));
        ret.headers.emplace_back("Content-Type", "application/json");
        ret.headers.emplace_back("Access-Control-Allow-Origin", "*");

        time_t uptime = time(nullptr) - SmithProxy::instance().ts_sys_started;

        nlohmann::json js = { { "version", SMITH_VERSION }, { "status", "ok" },
                              { "uptime", uptime },
                              { "uptime_str", uptime_string(uptime) } };
        response << to_string(js);

        return ret;
    }

};

#endif //HTTPD_HPP_