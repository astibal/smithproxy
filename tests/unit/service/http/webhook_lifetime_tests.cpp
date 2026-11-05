#include <gtest/gtest.h>
#include <service/http/async_request.hpp>
#include <proxy/proxy_hooks.hpp>
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
