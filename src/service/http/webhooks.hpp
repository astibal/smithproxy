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


#ifndef SX_HTTP_WEBHOOKS
#define SX_HTTP_WEBHOOKS

#include <string>
#include <atomic>
#include <memory>
#include <service/http/webhook_control.hpp>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <map>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <service/http/async_request.hpp>
#include <inspect/dnsinspector.hpp>


namespace sx::http::webhooks {

    struct refresh_gate {
        explicit refresh_gate(std::int64_t interval): interval(interval) {}

        bool acquire(std::int64_t now) {
            auto expected = next_allowed.load(std::memory_order_relaxed);
            while (now >= expected) {
                if (next_allowed.compare_exchange_weak(
                        expected, now + interval,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed))
                    return true;
            }
            return false;
        }

    private:
        const std::int64_t interval;
        std::atomic_int64_t next_allowed {0};
    };

    struct timestampq {
        explicit timestampq(std::size_t nevents, time_t period): maxlen(nevents), period(period) {};
        std::deque<time_t> q;
        std::size_t maxlen{0};
        time_t period{0};

        void add() {
            q.push_front(time(nullptr));
            if(q.size() > maxlen) { q.pop_back(); }
        };

        bool triggered() const {
            if(maxlen == 0 || q.size() < maxlen) return false;
            return q.front() >= q.back() && q.front() - q.back() <= period;
        }

        [[nodiscard]] std::optional<time_t> oldest() const {
            if(not q.empty()) {
                return q.back();
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<time_t> newest() const {
            if(not q.empty()) {
                return q.front();
            }
            return std::nullopt;
        }

    };

    struct url_stats {
        static inline std::size_t max_errors = 10;
        static inline time_t error_period = 300;
        static inline int this_expiry = 3600*24;
        std::string url;

        void update_incr(bool iferror) {
            if (iferror) {
                errorq.add();
            }
            total_counter++;
            ttl.set_expiry(time(nullptr) + this_expiry);
        }
        [[nodiscard]] bool is_error() const {
            return errorq.triggered();
        }
        [[nodiscard]] bool is_expired() const {
            return ttl.expired();
        }
        [[nodiscard]] std::size_t counter_total() const {
            return total_counter;
        }
        timestampq& errq() { return errorq; }
        timestampq const& errq() const { return errorq; }

    private:
        expiring_int ttl = expiring_int(0, this_expiry);
        std::size_t total_counter = 0;
        timestampq errorq = timestampq(max_errors, error_period);
    };

    std::mutex& url_stats_lock();
    std::unordered_map<std::string, url_stats>& url_stats_map();

    void ping();
    void ping_plus();
    void ping_neighbors();
    void set_enabled(bool val);
    bool is_enabled();
    void set_hostid(std::string const& ref);
    std::string get_hostid();
    bool sift_enabled();

    struct timing_diagnostics_snapshot {
        std::uint64_t samples = 0;
        double last_ms = 0.0;
        double average_ms = 0.0;
        double median_ms = 0.0;
        double p95_ms = 0.0;
        double min_ms = 0.0;
        double max_ms = 0.0;
    };

    struct webhook_diagnostics_snapshot {
        bool enabled = false;
        bool verify_tls = true;
        bool binary_content = false;
        std::string url;
        long timeout_seconds = 0;
        std::uint64_t requests = 0;
        std::uint64_t accepted = 0;
        std::uint64_t rejected = 0;
        std::uint64_t completed = 0;
        std::uint64_t succeeded = 0;
        std::uint64_t failed = 0;
        std::uint64_t asynchronous_requests = 0;
        std::uint64_t waiting_requests = 0;
        std::uint64_t action_requests = 0;
        std::uint64_t content_requests = 0;
        std::uint64_t request_bytes = 0;
        std::uint64_t response_bytes = 0;
        std::uint64_t last_request_ms = 0;
        std::uint64_t last_response_ms = 0;
        long last_status = 0;
        std::string last_error;
        std::map<std::string, std::uint64_t> actions;
        timing_diagnostics_snapshot total_delay;
        timing_diagnostics_snapshot queue_delay;
        timing_diagnostics_snapshot transport_delay;
    };

    [[nodiscard]] webhook_diagnostics_snapshot webhook_diagnostics();

    struct sift_diagnostics_snapshot {
        bool enabled = false;
        std::string url;
        std::string unix_socket_path;
        long timeout_seconds = 0;
        std::uint64_t requests = 0;
        std::uint64_t accepted = 0;
        std::uint64_t rejected = 0;
        std::uint64_t completed = 0;
        std::uint64_t succeeded = 0;
        std::uint64_t failed = 0;
        std::uint64_t action_requests = 0;
        std::uint64_t content_requests = 0;
        std::uint64_t request_bytes = 0;
        std::uint64_t response_bytes = 0;
        std::uint64_t last_request_ms = 0;
        std::uint64_t last_response_ms = 0;
        long last_status = 0;
        std::string last_error;
        double rtt_last_ms = 0.0;
        double rtt_average_ms = 0.0;
        double rtt_min_ms = 0.0;
        double rtt_max_ms = 0.0;
    };

    [[nodiscard]] sift_diagnostics_snapshot sift_diagnostics();
    bool send_sift_content_wait(
        std::string const& action_id, nlohmann::json details,
        std::string_view payload, sx::http::AsyncRequest::reply_hook hook);
    bool send_sift_action(
        std::string const& action, std::string const& action_id,
        nlohmann::json const& details);
    bool send_sift_dns_observation(DNS_Inspector::dns_observation const& observation);

    void neighbor_state(std::string const& address_str, std::string const& state);
    void neighbor_state(std::vector<std::string> const& address_vec, std::string const& state);
    void neighbor_new(std::string const& address_str);

    bool hostname_info(std::string const& origin, std::vector<std::string> const& addresses,
                       std::string const& hostname);
    bool hostname_info_dns_cache();

    void send_action(std::string const& action, nlohmann::json const& details);
    void send_action(std::string const& action, std::string const& action_id, nlohmann::json const& details,
                     std::shared_ptr<webhook_control_t> control = {});
    bool send_action_wait(std::string const& action, std::string const& action_id, nlohmann::json const& details, sx::http::AsyncRequest::reply_hook hook);
    bool send_content_wait(std::string const& action_id, nlohmann::json details,
                           std::string_view payload, sx::http::AsyncRequest::reply_hook hook);
    bool binary_content_enabled();
}

#endif
