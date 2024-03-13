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

    struct expected_reply_t {
        std::string request;
        std::pair<long,std::string> response;
    };
    using expected_reply = std::optional<expected_reply_t>;
    sx::http::expected_reply make_reply(std::string url, long code, std::string reply);


    class Request {
    private:
        CURL *curl;
        struct curl_slist *headers;
        std::string responseData;

    public:
        struct Initializator {
            Initializator() {
                curl_global_init(CURL_GLOBAL_DEFAULT);
            }
            ~Initializator() {
                curl_global_cleanup();
            }
        };

        static Initializator curl_initializator;

        unsigned int max_attmepts = 5;
        unsigned int attempts = 0;
        std::string debug_log;
        static inline bool DEBUG = true;
        static inline bool DEBUG_DUMP_OK = false;

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

        static std::string _make_ts() {
            auto now = std::chrono::system_clock::now();
            auto itt = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

            struct tm result{};
            gmtime_r(&itt, &result);

            std::ostringstream oss;
            oss << std::put_time(&result, "%Y-%m-%d--%H:%M:%S"); // Put time using UTC format into the stream.
            oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
            std::string timestamp(oss.str());

            return timestamp;
        }

        static int curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr) {
            // userptr points to your string or any other type of container
            std::string* debug_info = reinterpret_cast<std::string*>(userptr);
            switch (type) {
                case CURLINFO_TEXT:
                case CURLINFO_HEADER_IN:
                case CURLINFO_HEADER_OUT:
                case CURLINFO_DATA_IN:
                case CURLINFO_DATA_OUT:
                case CURLINFO_SSL_DATA_IN:
                case CURLINFO_SSL_DATA_OUT:
                {


                    std::string timestamp = _make_ts();

                    curl_socket_t fd;
                    CURLcode res = curl_easy_getinfo(handle, CURLINFO_ACTIVESOCKET, &fd);
                    if (res != CURLE_OK) {
                        fd = -1;  // or handle the error as appropriate
                    }
                    std::string prefix = timestamp + ": socket:" + std::to_string(fd) + ": ";
                    debug_info->append(prefix);
                    debug_info->append(data, size);
                    debug_info->append("\r\n");
                    break;
                }
                case CURLINFO_END:
                    break;
            }
            return 0;  // returning any other value than 0 will abort the operation!
        }


        void setup_debug() {
            if(DEBUG and curl) {
                curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
                curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &debug_log);
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            }
        }

        Request(IPVersion ip_version = DEFAULT, const std::string &dns_servers = "", const std::string &ca_path = "") {

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
            if(curl)
                curl_easy_cleanup(curl);
        }

        using Reply = sx::http::expected_reply;

        Reply emit(std::string const& url, std::string const& payload) {
            CURLcode res = CURLE_OK;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());


            for (; attempts < max_attmepts; ++attempts) {
                responseData.clear();
                res = curl_easy_perform(curl);

                if(res == CURLE_OK)
                    break;

                if(DEBUG) {
                    auto ts = _make_ts();
                    auto s = string_format("%s: attempt %d failed.\r\n", ts.c_str(), attempts);
                    debug_log.append(s);
                }
            }


            if (res != CURLE_OK) {
                return make_reply(url, 600, curl_easy_strerror(res));
            }

            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

            return make_reply(url, responseCode, responseData);
        }
    };
}


#endif