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

#include <service/helper_debug.hpp>
#include <iostream>
#include <string>
#include <optional>

#include <service/tpool.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/request.hpp>
#include <service/webhook/webhook_broker.hpp>
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
        static inline size_t max_pending = 256;
    };

    struct request_settings {
        bool enabled = false;
        bool sensitive = false;
        std::string url;
        std::string dns_servers;
        bool verify_tls = true;
        std::string bind_interface;
        std::string unix_socket_path;
        helper_debug::Service service = helper_debug::Service::webhook;
        std::uint64_t exchange_id = 0;
    };

    static inline std::atomic_size_t pending_requests = 0;
    static inline std::atomic_uint64_t dropped_requests = 0;

    using expected_reply = sx::http::expected_reply;
    using reply_hook = std::function<void(expected_reply const &)>;

    class RequestTask : public sx::tp::PoolTask {
      public:
        RequestTask(request_settings settings, std::string copy_pay, reply_hook hook,
                    bool counted = false)
            : sx::tp::PoolTask(), settings(std::move(settings)), payload(std::move(copy_pay)),
              hook(std::move(hook)), counted(counted) {};

        ~RequestTask() override {
            if (counted)
                pending_requests.fetch_sub(1, std::memory_order_relaxed);
        }

        void execute(std::atomic_bool const &stop_flag) override {
            if (stop_flag) {
                helper_debug::emit(settings.service, settings.exchange_id, "cancelled",
                                   "reason=worker-stopping");
                return;
            }
            if (log_stream.has_value()) {
                std::stringstream private_log;
                emit_url_wait_log(settings, payload, private_log, hook);
                // The worker marks this task finished under the pool lock
                // immediately after execute() returns. Diagnostics read
                // the published buffer only after observing that flag.
                log_stream->get().str(private_log.str());
            } else {
                std::stringstream log;
                emit_url_wait_log(settings, payload, log, hook);
            }
        }

        std::string info_short() const override {
            return string_format("web request: POST with %dB of data", payload.length());
        };
        std::string info_long() const override {
            return string_format("web request: POST %s with %dB of data", settings.url.c_str(),
                                 payload.length());
        };
        std::string info_detailed() const override {
            std::stringstream ss;
            ss << string_format("web request details: POST %s with %dB of data\n",
                                settings.url.c_str(), payload.length());
            if (!settings.sensitive)
                ss << "Payload: \n"
                   << hex_dump((unsigned char *)payload.data(), payload.length()) << "\n";
            ss << "-- \n";

            return ss.str();
        };

        void set_log_buffer(std::stringstream &ss) override {
            log_stream = ss;
        }

        void count_pending() {
            counted = true;
        }

      private:
        request_settings settings;
        std::string payload;
        reply_hook hook;
        std::optional<std::reference_wrapper<std::stringstream>> log_stream;
        bool counted = false;
    };

    static AsyncRequest &get() {
        std::call_once(once_flag, []() { asr = std::make_unique<AsyncRequest>(); });

        if (not asr) {
            throw AsyncRequestException("async request was not initialized");
        }

        return *asr;
    }

    static request_settings settings_snapshot() {
        request_settings settings;
        auto lc_ = std::scoped_lock(CfgFactory::lock());
        auto const &factory = CfgFactory::get();
        settings.enabled = factory->settings_webhook.enabled;
        settings.url = factory->settings_webhook.active_url();
        settings.verify_tls = factory->settings_webhook.active_tls_verify();
        settings.bind_interface = factory->settings_webhook.bind_interface;
        settings.unix_socket_path = sx::comm::webhook::transport_path();
        std::ostringstream dns;
        for (size_t i = 0; i < factory->db_nameservers.size(); ++i) {
            dns << factory->db_nameservers[i].str_host;
            if (i + 1 < factory->db_nameservers.size())
                dns << ',';
        }
        settings.dns_servers = dns.str();
        return settings;
    }

    static void invoke_hook(reply_hook const &hook, expected_reply const &reply) noexcept {
        try {
            hook(reply);
        } catch (std::exception const &error) {
            Log::get()->events().insert(ERR, "webhook callback failed: %s", error.what());
        } catch (...) {
            Log::get()->events().insert(ERR, "webhook callback failed: unknown exception");
        }
    }

    static void emit_url_wait(std::string const &url, std::string const &pay,
                              reply_hook const &hook) {
        std::stringstream ss;
        auto settings = settings_snapshot();
        settings.url = url;
        emit_url_wait_log(settings, pay, ss, hook);
    }

    // synchronous call, use emit_url() to use thread pool
    static void emit_url_wait_log(std::string const &url, std::string const &pay,
                                  std::stringstream &log, reply_hook const &hook) {
        auto settings = settings_snapshot();
        settings.url = url;
        emit_url_wait_log(settings, pay, log, hook);
    }

    static void emit_url_wait_log(request_settings const &settings, std::string const &pay,
                                  std::stringstream &log, reply_hook const &hook) {

        helper_debug::Exchange trace(
            settings.service,
            std::string("transport=") + (settings.unix_socket_path.empty() ? "http" : "http-unix") +
                " bytes=" + std::to_string(pay.size()),
            settings.exchange_id);
        if (helper_debug::enabled(settings.service, 9)) {
            auto endpoint = settings.url.substr(0, settings.url.find_first_of("?#"));
            const auto scheme = endpoint.find("://");
            const auto authority = scheme == std::string::npos ? 0 : scheme + 3;
            const auto slash = endpoint.find('/', authority);
            const auto at = endpoint.rfind('@', slash);
            if (at != std::string::npos && at >= authority)
                endpoint.erase(authority, at - authority + 1);
            helper_debug::emit(settings.service, trace.id(), "endpoint",
                               settings.sensitive ? "redacted" : helper_debug::field(endpoint), 9);
            helper_debug::emit(
                settings.service, trace.id(), "options",
                "timeout_s=" + std::to_string(settings.sensitive ? 3 : config::timeout) +
                    " verify_tls=" + std::to_string(settings.verify_tls),
                9);
        }
        if (!hook) {
            trace.finish("skipped", "reason=no-hook");
            return;
        }
        auto fail = [&hook, &settings, &trace](std::string message, const char *reason) {
            trace.finish("failed", std::string("reason=") + reason);
            expected_reply_t result;
            result.request = settings.url;
            result.response = {600, std::move(message)};
            invoke_hook(hook, expected_reply{std::move(result)});
        };

        if (settings.url.empty()) {
            fail("webhook URL is empty", "empty-url");
            return;
        }
        if (pay.empty()) {
            fail("webhook payload is empty", "empty-payload");
            return;
        }

        if (!settings.enabled) {
            fail("webhooks are disabled", "disabled");
            return;
        }

        try {
            log << make_ts() << ": init: settings: dns='" << settings.dns_servers
                << "' vrfy=" << settings.verify_tls << " bind_if='" << settings.bind_interface
                << "' unix_socket='" << settings.unix_socket_path << "'\n";

            Request request(Request::DEFAULT, settings.dns_servers);
            request.set_helper_diagnostics(settings.service, trace.id());

            // make custom setup
            request.set_timeout(settings.sensitive ? 3 : config::timeout);
            log << make_ts() << ": init: timeout='" << config::timeout << "\n";

            request.set_stale_detection();

            if (not settings.verify_tls)
                request.disable_tls_verify();
            if (not settings.unix_socket_path.empty()) {
                if (!request.set_unix_socket_path(settings.unix_socket_path))
                    throw AsyncRequestException("failed to configure webhook Unix transport");
            } else if (not settings.bind_interface.empty())
                request.set_interface(settings.bind_interface);

            // set debugging explicitly
            if (Request::DEBUG && !settings.sensitive) {
                log << make_ts() << ": init: extended debug is enabled\n";
                request.setup_curl_debug(log);
            }

            log << make_ts() << ": init: init_hook to start\n";
            auto init_hook_arg = request.make_reply(settings.url, -100, "");
            invoke_hook(hook, init_hook_arg);
            log << make_ts() << ": init: init_hook finished\n";

            log << make_ts() << ": work: request emit to start\n";
            helper_debug::emit(settings.service, trace.id(), "send",
                               "method=POST bytes=" + std::to_string(pay.size()));
            auto reply = request.emit(settings.url, pay);
            trace.finish("reply",
                         "status=" + std::to_string(reply ? reply->response.first : -1) +
                             " bytes=" + std::to_string(reply ? reply->response.second.size() : 0) +
                             " attempts=" + std::to_string(request.attempts));
            log << make_ts() << ": work: request emit finished\n";

            if (not reply or reply.value().response.first >= 300) {
                long code = reply.has_value() ? reply->response.first : -1;
                std::string msg = "request failed";
                if (reply.has_value() && !settings.sensitive)
                    msg = reply->response.second;

                Log::get()->events().insert(ERR, "error in request '%s' (attempts: %d): %d:%s",
                                            settings.url.c_str(), request.attempts, code,
                                            msg.c_str());
                log << make_ts() << ": finished: result is error: (code=" << code << ", msg='"
                    << msg << "'\n";

                if (Request::DEBUG && !settings.sensitive) {
                    Log::get()->events().insert(ERR, "error payload:\n >>>%s<<<", pay.c_str());
                    Log::get()->events().insert(ERR, "error trace:\n %s", log.str().c_str());
                }
            } else if (Request::DEBUG and Request::DEBUG_DUMP_OK) {
                auto const &rp = reply.value().response;
                log << make_ts() << ": finished: result is OK (code=" << rp.first
                    << ", sz=" << rp.second.size() << "B)\n";
            }
            log << make_ts() << ": finished: hook to start\n";
            invoke_hook(hook, reply);
            log << make_ts() << ": finished: hook finished\n";
        } catch (std::exception const &error) {
            Log::get()->events().insert(ERR, "webhook request failed before completion: %s",
                                        error.what());
            fail(std::string("webhook request failed: ") + error.what(), "exception");
        } catch (...) {
            Log::get()->events().insert(
                ERR, "webhook request failed before completion: unknown exception");
            fail("webhook request failed: unknown exception", "unknown-exception");
        }
    }

    static void emit_wait(std::string const &pay, reply_hook const &hook) {
        std::stringstream log;
        emit_url_wait_log(settings_snapshot(), pay, log, hook);
    }

    static bool enqueue(request_settings settings, std::string const &pay, reply_hook const &hook) {
        if (!settings.exchange_id)
            settings.exchange_id = helper_debug::next_id();
        const auto service = settings.service;
        const auto id = settings.exchange_id;
        if (!settings.enabled || settings.url.empty() || pay.empty() || !hook ||
            SmithProxy::instance().terminate_flag) {
            const auto reason = !settings.enabled      ? "disabled"
                                : settings.url.empty() ? "empty-url"
                                : pay.empty()          ? "empty-payload"
                                : !hook                ? "no-hook"
                                                       : "stopping";
            helper_debug::emit(service, id, "skipped", std::string("reason=") + reason);
            return false;
        }

        auto task = std::make_unique<RequestTask>(std::move(settings), pay, hook);

        size_t pending = pending_requests.load(std::memory_order_relaxed);
        do {
            if (pending >= config::max_pending) {
                helper_debug::emit(service, id, "rejected", "reason=queue-full");
                dropped_requests.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        } while (!pending_requests.compare_exchange_weak(pending, pending + 1,
                                                         std::memory_order_relaxed));
        task->count_pending();

        auto &pool = sx::tp::ThreadPool::instance::get();
        auto ret = pool.enqueue(std::move(task));
        if (ret <= 0)
            dropped_requests.fetch_add(1, std::memory_order_relaxed);
        helper_debug::emit(service, id, ret > 0 ? "queued" : "rejected",
                           "bytes=" + std::to_string(pay.size()) +
                               " pending=" + std::to_string(pending_requests.load()));
        return ret > 0;
    };

    // Retirement cannot retain the proxy until a later queue retry: its owner
    // destroys it immediately after finalize(). If the bounded queue rejects
    // a terminal notification, perform one direct, timeout-bounded request.
    // Accepted jobs are never repeated here (enqueue is not HTTP delivery).
    static void emit_terminal(request_settings const &settings, std::string const &pay,
                              reply_hook const &hook) {
        auto effective = settings;
        if (!effective.exchange_id)
            effective.exchange_id = helper_debug::next_id();
        if (enqueue(effective, pay, hook))
            return;
        helper_debug::emit(effective.service, effective.exchange_id, "fallback",
                           "mode=synchronous");
        std::stringstream log;
        emit_url_wait_log(effective, pay, log, hook);
    }

    static bool emit_url(std::string const &url, std::string const &pay, reply_hook const &hook) {
        auto settings = settings_snapshot();
        settings.url = url;
        return enqueue(std::move(settings), pay, hook);
    };

    static bool emit(std::string const &pay, reply_hook const &hook) {
        return enqueue(settings_snapshot(), pay, hook);
    }
};
} // namespace sx::http

#endif
