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
#include <algorithm>
#include <chrono>
#include <limits>
#include <thread>
#include <curl/curl.h>
#include <optional>
#include <service/core/smithproxy.hpp>
#include <service/tpool.hpp>

namespace sx::http {

    class Request;

    struct expected_reply_t {
        Request* ctrl = nullptr;
        std::string request;
        std::pair<long,std::string> response {};
    };
    using expected_reply = std::optional<expected_reply_t>;


    class Request {
    private:
        CURL *curl;
        struct curl_slist *headers;
        std::string responseData;
        long timeout_seconds_ = 5;
        size_t max_response_size_ = 8U * 1024U * 1024U;

        struct write_context_t {
            std::string* output = nullptr;
            size_t max_size = 0;
            bool overflow = false;
        } write_context {&responseData, max_response_size_, false};

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

        unsigned int max_attempts = 2;
        unsigned int attempts = 0;
        std::stringstream* debug_log = nullptr;
        static inline bool DEBUG = false;
        static inline bool DEBUG_DUMP_OK = false;

        struct progress {

            struct progress_t {
                char* ptr = nullptr;
                size_t size = 0;
            };

            static inline thread_local progress_t data {nullptr, 0};

            static size_t _write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
                auto* context = static_cast<write_context_t*>(userp);
                if (!context || !context->output ||
                    (size != 0 && nmemb > std::numeric_limits<size_t>::max() / size)) {
                    return 0;
                }
                const size_t bytes = size * nmemb;
                if (bytes > context->max_size - std::min(context->max_size,
                                                          context->output->size())) {
                    context->overflow = true;
                    return 0;
                }
                context->output->append(static_cast<char*>(contents), bytes);
                return bytes;
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

        sx::http::expected_reply make_reply(std::string url, long code, std::string reply);


        // this is not good idea, but good to have for testing
        void disable_tls_verify() {
            if(curl) {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            }
        }

        void set_timeout(long seconds) {
            if(curl && seconds > 0) {
                timeout_seconds_ = seconds;
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, seconds);
            }
        }

        void set_max_response_size(size_t bytes) {
            max_response_size_ = bytes;
            write_context.max_size = bytes;
        }

        void set_stale_detection(long seconds=30) {

            if(curl) {
                // set also low-speed detection
                curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, seconds);
                curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
            }
        }

        void set_interface(std::string const& intf) {
            if(curl and not intf.empty()) {
                curl_easy_setopt(curl, CURLOPT_INTERFACE, intf.c_str());
            }
        }

        bool set_unix_socket_path(std::string const& path) {
            return curl && !path.empty()
                && curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, path.c_str()) == CURLE_OK;
        }


        static int curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr) {
            // userptr points to your string or any other type of container
            auto& debug_info = *reinterpret_cast<std::stringstream*>(userptr);
            std::string timestamp = make_ts();

            switch (type) {
                case CURLINFO_TEXT:
                    debug_info << timestamp << ": ";
                    debug_info << std::string(data, size);
                    break;

                case CURLINFO_HEADER_IN:
                case CURLINFO_HEADER_OUT:
                case CURLINFO_DATA_IN:
                case CURLINFO_DATA_OUT:
                case CURLINFO_SSL_DATA_IN:
                case CURLINFO_SSL_DATA_OUT:
                {
                    if(DEBUG_DUMP_OK) {
                        debug_info << timestamp << ": ";
                        debug_info << std::string(data, size);
                    }
                    break;
                }
                case CURLINFO_END:
                    break;
            }
            return 0;  // returning any other value than 0 will abort the operation!
        }

        void setup_curl_debug(std::stringstream& curl_log) {
            if(DEBUG and curl) {
                debug_log = &curl_log;
                curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
                curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &curl_log);
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
            if (!headers) {
                curl_easy_cleanup(curl);
                curl = nullptr;
                throw std::runtime_error("Failed to initialize CURL headers.");
            }
            // Large POSTs otherwise use Expect: 100-continue. Webhook peers
            // and HTTP intermediaries often do not answer the interim request,
            // adding a visible delay before cURL sends the body.
            if (auto* updated = curl_slist_append(headers, "Expect:")) {
                headers = updated;
            }
            else {
                curl_slist_free_all(headers);
                headers = nullptr;
                curl_easy_cleanup(curl);
                curl = nullptr;
                throw std::runtime_error("Failed to initialize CURL headers.");
            }

            // Set up common options
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 10L);

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, progress::_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_context);
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

            // Enable the progress function
            curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress::data);
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress::callback);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

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
            if(headers)
                curl_slist_free_all(headers);
        }

        Request(Request const&) = delete;
        Request& operator=(Request const&) = delete;
        Request(Request&&) = delete;
        Request& operator=(Request&&) = delete;

        using Reply = sx::http::expected_reply;

        Reply emit(std::string const& url, std::string const& payload) {
            CURLcode res = CURLE_FAILED_INIT;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                             static_cast<curl_off_t>(payload.size()));

            attempts = 0;
            const auto deadline = std::chrono::steady_clock::now()
                                  + std::chrono::seconds(timeout_seconds_);
            while (attempts < max_attempts) {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now()).count();
                if (remaining <= 0) {
                    res = CURLE_OPERATION_TIMEDOUT;
                    break;
                }
                curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, std::max<long long>(1, remaining));
                responseData.clear();
                write_context.overflow = false;
                ++attempts;
                res = curl_easy_perform(curl);

                auto do_log = (DEBUG and debug_log);

                if(res == CURLE_OK) {
                    if(do_log) {
                        auto ts = make_ts();
                        auto s = string_format("%s: attempt #%d OK.\r\n", ts.c_str(), attempts);

                        *debug_log <<  s;
                    }
                    break;
                }
                else if(do_log){
                    auto ts = make_ts();
                    auto s = string_format("%s: attempt #%d failed.\r\n", ts.c_str(), attempts);

                    *debug_log <<  s;
                }

                const bool safe_to_retry = res == CURLE_COULDNT_RESOLVE_PROXY
                                           || res == CURLE_COULDNT_RESOLVE_HOST
                                           || res == CURLE_COULDNT_CONNECT;
                if (!safe_to_retry || attempts >= max_attempts) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }


            if (res != CURLE_OK) {
                if (write_context.overflow)
                    return make_reply(url, 600, "webhook response exceeds configured limit");
                return make_reply(url, 600, curl_easy_strerror(res));
            }

            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

            return make_reply(url, responseCode, responseData);
        }
    };
}


#endif
