#include <gtest/gtest.h>
#include <service/helper_log.hpp>
#include <service/http/async_request.hpp>
#include <proxy/proxy_hooks.hpp>
#include <proxy/retirement.hpp>
#include <future>
#include <thread>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

struct HelperHttpRecord { std::uint64_t id; std::string event; std::string detail; };
std::mutex helper_http_mutex;
std::vector<HelperHttpRecord> helper_http_records;
struct CaptureHelperHttp {
    sx::helper_debug::Sink previous;
    CaptureHelperHttp() {
        helper_http_records.clear();
        previous = sx::helper_debug::sink.exchange(+[](sx::helper_debug::Service, int,
                std::uint64_t id, std::string_view event, std::string_view detail) {
            std::lock_guard lock(helper_http_mutex);
            helper_http_records.push_back({id, std::string(event), std::string(detail)});
        });
    }
    ~CaptureHelperHttp() { sx::helper_debug::sink.store(previous); }
};

class HeldWebhookWorker final : public sx::tp::PoolTask {
public:
    explicit HeldWebhookWorker(std::shared_future<void> release)
        : release_(std::move(release)) {}

    void execute(const std::atomic_bool&) override { release_.wait(); }
    std::string info_short() const override { return "held webhook worker"; }
    std::string info_long() const override { return info_short(); }
    std::string info_detailed() const override { return info_short(); }

private:
    std::shared_future<void> release_;
};

} // namespace

TEST(WebhookLifetime, QueuedRequestSurvivesItsSourceSnapshot) {
    using Request = sx::http::AsyncRequest;

    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int bound = bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if(bound != 0) {
        close(listener);
        FAIL() << "Cannot bind test receiver";
    }
    ASSERT_EQ(listen(listener, 1), 0);
    socklen_t address_size = sizeof(address);
    ASSERT_EQ(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size), 0);

    CaptureHelperHttp capture;
    const std::string expected = nlohmann::json({{"message", std::string(4096, 'x')}}).dump();
    std::promise<std::string> received;
    auto received_future = received.get_future();
    std::thread receiver([&] {
        std::string wire;
        pollfd ready{listener, POLLIN, 0};
        if(poll(&ready, 1, 10000) > 0) {
            const int client = accept(listener, nullptr, nullptr);
            if(client >= 0) {
                timeval timeout{5, 0};
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                char buffer[2048];
                while(wire.find(expected) == std::string::npos) {
                    const auto count = recv(client, buffer, sizeof(buffer), 0);
                    if(count <= 0) break;
                    wire.append(buffer, static_cast<std::size_t>(count));
                }
                const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                send(client, response.data(), response.size(), MSG_NOSIGNAL);
                close(client);
            }
        }
        received.set_value(std::move(wire));
    });

    std::promise<void> release;
    auto gate = release.get_future().share();
    sx::tp::ThreadPool pool(1);
    pool.enqueue(std::make_unique<HeldWebhookWorker>(gate));

    auto callback_alive = std::make_shared<int>(42);
    std::weak_ptr<int> callback_lifetime = callback_alive;
    {
        auto snapshot = std::make_unique<sx::proxy::ProxyHooks::Epitaph>();
        snapshot->connection_id = "retired-session";
        snapshot->details = {{"message", std::string(4096, 'x')}};

        Request::request_settings settings;
        settings.exchange_id = 12345;
        settings.enabled = true;
        settings.url = "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/";
        const auto payload = snapshot->details.dump();
        auto callback = [owned = callback_alive](const Request::expected_reply&) {
            EXPECT_EQ(*owned, 42);
        };

        pool.enqueue(std::make_unique<Request::RequestTask>(settings, payload, callback));
    }
    callback_alive.reset();

    // Payload, settings, callback and epitaph have all left their source scope.
    // Only now may the worker serialize the request onto the socket.
    EXPECT_FALSE(callback_lifetime.expired());
    release.set_value();
    receiver.join();
    close(listener);

    EXPECT_NE(received_future.get().find(expected), std::string::npos);
    pool.shutdown();
    EXPECT_TRUE(callback_lifetime.expired());
    ASSERT_FALSE(helper_http_records.empty());
    bool sent = false, replied = false;
    for(auto const& record : helper_http_records) {
        EXPECT_EQ(record.id, 12345U);
        EXPECT_EQ(record.detail.find(std::string(32, 'x')), std::string::npos);
        if(record.event == "send") sent = true;
        if(record.event == "reply") {
            EXPECT_TRUE(sent);
            EXPECT_NE(record.detail.find("status=200"), std::string::npos);
            replied = true;
        }
    }
    EXPECT_TRUE(replied);
}

TEST(WebhookRetirement, FailingHookAndFailingDiagnosticDoNotSkipStop) {
    bool stop_attempted = false;
    auto snapshot = std::make_unique<sx::proxy::ProxyHooks::Epitaph>();
    snapshot->connection_id = "retired-session";
    snapshot->details = {{"info", {{"bytes_up", 12}}}};
    EXPECT_FALSE(sx::proxy::retirement_step([] { throw std::runtime_error("hook"); },
                                          [] { throw std::runtime_error("logger"); }));
    EXPECT_TRUE(sx::proxy::retirement_step([&] {
        stop_attempted = true;
        EXPECT_EQ(snapshot->connection_id, "retired-session");
        EXPECT_EQ(snapshot->details["info"]["bytes_up"], 12);
    }, [] { FAIL() << "stop unexpectedly failed"; }));
    EXPECT_TRUE(stop_attempted);
}

namespace {

// Exercise the real admission gate, libcurl request and receiver, not a mocked
// enqueue result. Zero queue capacity deterministically forces the fallback.
void terminal_delivery(bool saturated) {
    using Request = sx::http::AsyncRequest;
    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    ASSERT_EQ(listen(listener, 4), 0);
    socklen_t size = sizeof(address);
    ASSERT_EQ(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size), 0);

    const std::string payload = R"({"action":"connection-stop","id":"retired-session"})";
    std::promise<std::string> received;
    auto wire = received.get_future();
    std::atomic_int requests{0};
    std::thread receiver([&] {
        std::string message;
        pollfd ready{listener, POLLIN, 0};
        while(poll(&ready, 1, requests == 0 ? 5000 : 200) > 0) {
            const int client = accept(listener, nullptr, nullptr);
            if(client < 0) break;
            ++requests;
            timeval timeout{2, 0};
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            char buffer[1024];
            while(message.find(payload) == std::string::npos) {
                const auto count = recv(client, buffer, sizeof(buffer), 0);
                if(count <= 0) break;
                message.append(buffer, count);
            }
            const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            send(client, response.data(), response.size(), MSG_NOSIGNAL);
            close(client);
        }
        received.set_value(std::move(message));
    });

    const auto capacity = Request::config::max_pending;
    if(saturated) Request::config::max_pending = 0;
    Request::request_settings settings;
    settings.enabled = true;
    settings.url = "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/";
    auto completed = std::make_shared<std::promise<long>>();
    auto status = completed->get_future();
    Request::emit_terminal(settings, payload, [completed](const Request::expected_reply& reply) {
        if(reply && reply->response.first != -100) completed->set_value(reply->response.first);
    });
    receiver.join();
    EXPECT_EQ(status.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    if(status.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        EXPECT_EQ(status.get(), 200);
    }
    EXPECT_NE(wire.get().find(payload), std::string::npos);
    EXPECT_EQ(requests, 1); // accepted async jobs must never also take the fallback
    Request::config::max_pending = capacity;
    close(listener);
}
} // namespace

TEST(WebhookRetirement, FullQueueFallsBackToDirectDelivery) { terminal_delivery(true); }
TEST(WebhookRetirement, DaemonShutdownReportsTransportFailure) {
    // Global daemon termination aborts libcurl by design. Unlike session
    // retirement, it cannot promise delivery; it must still report failure.
    if(!Log::instance()) Log::init();
    using Request = sx::http::AsyncRequest;
    const auto previous = SmithProxy::instance().terminate_flag.exchange(true);
    Request::request_settings settings;
    settings.enabled = true;
    settings.url = "http://127.0.0.1:1/";
    int failures = 0;
    Request::emit_terminal(settings, "stop", [&](auto const& reply) {
        if(reply && reply->response.first == -100) return;
        ++failures;
        EXPECT_TRUE(reply.has_value());
        if(reply) { EXPECT_EQ(reply->response.first, 600); }
    });
    SmithProxy::instance().terminate_flag = previous;
    EXPECT_EQ(failures, 1);
}
TEST(WebhookRetirement, AcceptedQueueJobIsNotSentTwice) { terminal_delivery(false); }

TEST(WebhookRetirement, DisabledDestinationReportsFailureWithoutNetworkIO) {
    sx::http::AsyncRequest::request_settings settings;
    settings.url = "http://127.0.0.1:1/";
    int callbacks = 0;
    sx::http::AsyncRequest::emit_terminal(settings, "stop", [&](auto const& reply) {
        ++callbacks;
        ASSERT_TRUE(reply.has_value());
        EXPECT_EQ(reply->response.first, 600);
    });
    EXPECT_EQ(callbacks, 1);
}

TEST(HelperHttpDebug, RejectedRequestHasReasonAndDoesNotLeakEndpointSecrets) {
    CaptureHelperHttp capture;
    sx::http::AsyncRequest::request_settings settings;
    settings.exchange_id = 54321;
    settings.url = "http://user:password@localhost/endpoint?token=secret";
    std::stringstream log;
    sx::http::AsyncRequest::emit_url_wait_log(settings, "private-body", log, [](auto const&) {});
    ASSERT_FALSE(helper_http_records.empty());
    EXPECT_EQ(helper_http_records.back().event, "failed");
    for(auto const& record : helper_http_records) {
        EXPECT_EQ(record.id, 54321U);
        EXPECT_NE(record.event, "send");
        for(auto word : {"password", "secret", "private-body"})
            EXPECT_EQ(record.detail.find(word), std::string::npos);
    }
}

TEST(HelperLogging, CategoryAndTerminalLevelsWorkWithoutInternalDebug) {
    using namespace sx::helper_debug;
    const auto old_sink = sink.load();
    const auto old_filter = filter.load();
    install_logging();
    EXPECT_NE(logan::get()->topic_db_.find("sys.sift"), logan::get()->topic_db_.end());
    auto& sift = loggers()[static_cast<std::size_t>(Service::sift)];
    const auto previous_sift = *sift.level();
    const auto previous_common = *common_logger().level();
    sift.level(loglevel(8));
    common_logger().level(loglevel(0));
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    auto profile = std::make_shared<logger_profile>();
    profile->level_ = loglevel(8);
    ASSERT_TRUE(Log::get()->add_remote_target("helper-test", sockets[0], profile));
    const auto previous_internal = Log::get()->level();
    Log::get()->level(loglevel(0));
    emit(Service::sift, 42, "send", "bytes=17");
    char bytes[2048]{};
    const auto size = recv(sockets[1], bytes, sizeof(bytes), MSG_DONTWAIT);
    ASSERT_GT(size, 0);
    const std::string message(bytes, size);
    EXPECT_NE(message.find("sys.sift"), std::string::npos);
    EXPECT_NE(message.find("exchange=42"), std::string::npos);
    EXPECT_NE(message.find("bytes=17"), std::string::npos);
    emit(Service::sift, 43, "detail", "hidden", 9);
    EXPECT_EQ(recv(sockets[1], bytes, sizeof(bytes), MSG_DONTWAIT), -1);
    sift.level(loglevel(0));
    common_logger().level(loglevel(8));
    emit(Service::sift, 44, "reply", "status=200");
    EXPECT_GT(recv(sockets[1], bytes, sizeof(bytes), MSG_DONTWAIT), 0);
    Log::get()->remove_remote_target(sockets[0]);
    close(sockets[0]);
    close(sockets[1]);
    Log::get()->level(previous_internal);
    sift.level(previous_sift);
    common_logger().level(previous_common);
    sink.store(old_sink);
    filter.store(old_filter);
}

TEST(HelperHttpDebug, ConnectionFailureReportsRetriesAndCurlReason) {
    CaptureHelperHttp capture;
    // Reserve a loopback port without listening: connect must be refused.
    const int reservation = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(reservation, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(reservation, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    socklen_t size = sizeof(address);
    ASSERT_EQ(getsockname(reservation, reinterpret_cast<sockaddr*>(&address), &size), 0);
    sx::http::Request request;
    request.set_helper_diagnostics(sx::helper_debug::Service::sift, 9876);
    const auto response = request.emit("http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)), "secret-content");
    close(reservation);
    ASSERT_TRUE(response);
    EXPECT_EQ(response->response.first, 600);
    unsigned attempts = 0, retries = 0;
    for(auto const& record : helper_http_records) {
        EXPECT_EQ(record.id, 9876U);
        EXPECT_EQ(record.detail.find("secret-content"), std::string::npos);
        if(record.event == "attempt-result") {
            ++attempts;
            EXPECT_NE(record.detail.find("curl=" + std::to_string(CURLE_COULDNT_CONNECT)), std::string::npos);
        }
        if(record.event == "retry") ++retries;
    }
    EXPECT_EQ(attempts, 2U);
    EXPECT_EQ(retries, 1U);
    EXPECT_EQ(helper_http_records.back().event, "transport-error");
}
