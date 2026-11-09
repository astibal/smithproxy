#include <gtest/gtest.h>
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
