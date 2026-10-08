#include <service/comm.hpp>

#include <atomic>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

class OneWayOperation final : public sx::comm::Operation {
public:
    sx::comm::Reply execute(const sx::comm::Request& request) override {
        payload = request.payload;
        calls.fetch_add(1);
        return {};
    }

    bool one_way() const noexcept override { return true; }

    std::atomic<unsigned> calls{0};
    std::string payload;
};

TEST(CommTest, OneWayOperationDoesNotRequireAReply) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Server server(channels[1]);
    auto operation = std::make_shared<OneWayOperation>();
    ASSERT_EQ(server.register_operation(42, operation), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    {
        sx::comm::Client client(channels[0], std::chrono::milliseconds(100));
        ::close(channels[0]);
        ::close(channels[1]);
        ASSERT_EQ(client.set_nonblocking(), 0);
        EXPECT_EQ(client.notify(42, "gre-frame"), 0);
    }
    helper.join();
    EXPECT_EQ(operation->calls.load(), 1U);
    EXPECT_EQ(operation->payload, "gre-frame");
}

} // namespace
