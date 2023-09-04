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


#ifndef SX_HTTP_REQUEST
#define SX_HTTP_REQUEST

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <optional>
#include <service/core/smithproxy.hpp>
#include <service/tpool.hpp>

namespace sx::http {

    class Request {
    private:
        CURL *curl;
        struct curl_slist *headers;
        std::string responseData;



    public:

        struct progress {

            struct progress_t {
                char* ptr = nullptr;
                size_t size = 0;
            };

            static inline thread_local progress_t data {nullptr, 0};

            static size_t _write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
                ((std::string *) userp)->append((char *) contents, size * nmemb);
                return size * nmemb;
            }

            static int callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                         curl_off_t ulnow) {
                if (SmithProxy::instance().terminate_flag) {
                    return 1;
                }
                return 0;
            }
        };

        enum IPVersion {
            DEFAULT,
            IPV4_ONLY,
            IPV6_ONLY
        };

        // this is not good idea, but good to have for testing
        void disable_tls_verify() {
            if(curl)
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        }

        void set_timeout(long seconds) {
            if(curl)
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, seconds);
        }

        Request(IPVersion ip_version = DEFAULT, const std::string &dns_servers = "", const std::string &ca_path = "") {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();

            if (!curl) {
                throw std::runtime_error("Failed to initialize CURL.");
            }

            headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            // Set up common options
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, progress::_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

            // Enable the progress function
            curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress::data);
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress::callback);

            // IP version handling
            switch (ip_version) {
                case IPV4_ONLY:
                    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
                    break;
                case IPV6_ONLY:
                    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
                    break;
                default:
                    break;
            }

            // Set DNS servers if provided
            if (!dns_servers.empty()) {
                curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, dns_servers.c_str());
            }

            // Set CA path if provided
            if (!ca_path.empty()) {
                curl_easy_setopt(curl, CURLOPT_CAPATH, ca_path.c_str());
            }
        }

        ~Request() {


            curl_global_cleanup();
        }

        using Reply = std::optional<std::pair<long, std::string>>;

        Reply emit(std::string const& url, std::string const& payload) {
            CURLcode res;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());

            responseData.clear();
            res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                return std::nullopt;
            }

            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

            return std::make_pair(responseCode, responseData);
        }
    };
}


#endif