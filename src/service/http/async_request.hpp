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

#ifndef SX_HTTP_ASYNCREQUEST
#define SX_HTTP_ASYNCREQUEST

#include <iostream>
#include <string>
#include <optional>

#include <service/tpool.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/request.hpp>
#include <log/logger.hpp>

namespace sx::http {

    class AsyncRequestException : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };



    class AsyncRequest {
        static inline std::once_flag once_flag;
        static inline std::unique_ptr<AsyncRequest> asr;

    public:

        struct config {
            static inline long timeout = 5;
        };

        using expected_reply = sx::http::expected_reply;
        using reply_hook = std::function<void(expected_reply const&)>;


        class RequestTask : public sx::tp::PoolTask {
        public:
            RequestTask(std::string const& copy_url, std::string const& copy_pay, reply_hook  hook):
            sx::tp::PoolTask(), url(copy_url), payload(copy_pay), hook(hook) {};

            void execute(std::atomic_bool const& stop_flag) override {
                if(log_stream.has_value()) {
                    emit_url_wait_log(url, payload, log_stream.value(), hook);
                }
                else {
                    emit_url_wait(url, payload, hook);
                }
            }

            std::string info_short() const override {
                return string_format("web request: POST with %dB of data", payload.length()); };
            std::string info_long() const override {
                return string_format("web request: POST %s with %dB of data", url.c_str(), payload.length());
            };
            std::string info_detailed() const override {
                std::stringstream ss;
                ss << string_format("web request details: POST %s with %dB of data\n", url.c_str(), payload.length());
                ss << "Payload: \n" << hex_dump((unsigned char*)payload.data(), payload.length()) << "\n";
                ss << "-- \n";

                return ss.str();
            };

            void set_log_buffer(std::stringstream& ss) override {
                log_stream = ss;
            }


        private:
            std::string url;
            std::string payload;
            reply_hook hook;
            std::optional<std::reference_wrapper<std::stringstream>> log_stream;
        };

        static AsyncRequest& get() {
            std::call_once(once_flag, []() {
                asr = std::make_unique<AsyncRequest>();
            });

            if(not asr) {
                throw AsyncRequestException("async request was not initialized");
            }

            return *asr;
        }


        static void emit_url_wait(std::string const& url, std::string const& pay, reply_hook const& hook) {
            std::stringstream ss;
            emit_url_wait_log(url, pay, ss, hook);
        }

        // synchronous call, use emit_url() to use thread pool
        static void emit_url_wait_log(std::string const& url, std::string const& pay, std::stringstream& log, reply_hook const& hook) {

            if(url.empty() or pay.empty()) return;

            std::string dns_servers;
            bool do_verify = true;
            std::string bind_if;
            {
                auto lc_ = std::scoped_lock(CfgFactory::lock());
                auto is_enabled = CfgFactory::get()->settings_webhook.enabled;

                if(not is_enabled) {
                    return; // not an error, we just don't use webhooks
                }

                auto const &nms = CfgFactory::get()->db_nameservers;

                std::ostringstream oss;
                for (size_t i = 0; i < nms.size(); ++i) {
                    oss << nms[i].str_host;     // loaded from config, string should always be there
                    if (i < nms.size() - 1) {
                        oss << ",";
                    }
                }
                dns_servers = oss.str();
                do_verify = CfgFactory::get()->settings_webhook.active_tls_verify();
                bind_if = CfgFactory::get()->settings_webhook.bind_interface;
            }
            log << make_ts() << ": init: settings: dns='" << dns_servers << "' vrfy=" << do_verify << " bind_if='" << bind_if << "'\n";

            Request request(Request::DEFAULT, dns_servers);

            // make custom setup
            request.set_timeout(config::timeout);
            log << make_ts() << ": init: timeout='" << config::timeout << "\n";

            request.set_stale_detection();

            if(not do_verify) request.disable_tls_verify();
            if(not bind_if.empty()) request.set_interface(bind_if);

            // set debugging explicitly
            if(Request::DEBUG) {
                log << make_ts() << ": init: extended debug is enabled\n";
                request.setup_curl_debug(log);
            }

            log << make_ts() << ": init: init_hook to start\n";
            auto init_hook_arg = request.make_reply(url, -100, "");
            hook(init_hook_arg);
            log << make_ts() << ": init: init_hook finished\n";

            log << make_ts() << ": work: request emit to start\n";
            auto reply = request.emit(url, pay);
            log << make_ts() << ": work: request emit finished\n";

            if(not reply or reply.value().response.first >= 300) {
                long code = reply.has_value() ? reply->response.first : -1;
                std::string msg = reply.has_value() ? reply->response.second : "request failed";

                Log::get()->events().insert(ERR, "error in request '%s' (retries: %d): %d:%s", url.c_str(), request.attempts, code, msg.c_str());
                log << make_ts() << ": finished: result is error: (code="<< code << ", msg='" << msg << "'\n";


                if(Request::DEBUG) {
                    Log::get()->events().insert(ERR, "error payload:\n >>>%s<<<", pay.c_str());
                    Log::get()->events().insert(ERR, "error trace:\n %s", log.str().c_str());
                }
            }
            else if(Request::DEBUG and Request::DEBUG_DUMP_OK) {
                auto const& rp = reply.value().response;
                log << make_ts() << ": finished: result is OK (code="<< rp.first << ", sz="<< rp.second.size() << "B)\n";
            }
            log << make_ts() << ": finished: hook to start\n";
            hook(reply);
            log << make_ts() << ": finished: hook finished\n";
        }

        static void emit_wait(std::string const& pay, reply_hook const& hook) {
            std::string url;
            {
                auto lc_ = std::scoped_lock(CfgFactory::lock());
                url = CfgFactory::get()->settings_webhook.active_url();
            }

            emit_url_wait(url, pay, hook);
        }

        static bool emit_url(std::string const& url, std::string const& pay, reply_hook const& hook) {
            auto &pool = sx::tp::ThreadPool::instance::get();

            // add extra safety and copy values, to make them copyable in thread lambda capture
            std::string copy_url(url);
            std::string copy_pay(pay);

            auto task = std::make_unique<RequestTask>(copy_url, copy_pay, hook);
            auto ret = pool.enqueue(std::move(task));

            return (ret > 0);
        };

        static bool emit(std::string const& pay, reply_hook const& hook) {
            std::string url;
            {
                auto lc_ = std::scoped_lock(CfgFactory::lock());
                url = CfgFactory::get()->settings_webhook.active_url();
            }

            return emit_url(url, pay, hook);
        }

    };
}

#endif