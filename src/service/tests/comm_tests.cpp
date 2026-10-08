#include <service/comm.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstring>
#include <random>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <sys/socket.h>
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

TEST(CommTest, OversizedDatagramDoesNotTerminateServer) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Server server(channels[1]);
    auto operation = std::make_shared<OneWayOperation>();
    ASSERT_EQ(server.register_operation(42, operation), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    std::vector<std::byte> oversized(128U * 1024U, std::byte{'X'});
    ASSERT_EQ(::send(channels[0], oversized.data(), oversized.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(oversized.size()));
    {
        sx::comm::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        EXPECT_EQ(client.notify(42, "after-oversized"), 0);
        for(unsigned attempt = 0; attempt < 100 && operation->calls.load() == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        EXPECT_EQ(operation->calls.load(), 1U);
        EXPECT_EQ(operation->payload, "after-oversized");
    }
    helper.join();
}

TEST(CommTest, ExcessDescriptorsDoNotTerminateServerOrLeakIntoNextRequest) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Server server(channels[1]);
    auto operation = std::make_shared<OneWayOperation>();
    ASSERT_EQ(server.register_operation(42, operation), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    int descriptors[3]{};
    for(int& descriptor: descriptors) {
        descriptor = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT_GE(descriptor, 0);
    }
    std::byte payload{std::byte{'X'}};
    iovec iov{&payload, sizeof(payload)};
    std::array<std::byte, CMSG_SPACE(sizeof(descriptors))> control{};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* cmsg = CMSG_FIRSTHDR(&message);
    ASSERT_NE(cmsg, nullptr);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(descriptors));
    std::memcpy(CMSG_DATA(cmsg), descriptors, sizeof(descriptors));
    ASSERT_EQ(::sendmsg(channels[0], &message, MSG_NOSIGNAL), 1);
    for(int descriptor: descriptors) ::close(descriptor);

    {
        sx::comm::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        EXPECT_EQ(client.notify(42, "after-descriptor-spam"), 0);
        for(unsigned attempt = 0; attempt < 100 && operation->calls.load() == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        EXPECT_EQ(operation->calls.load(), 1U);
        EXPECT_EQ(operation->payload, "after-descriptor-spam");
    }
    helper.join();
}

TEST(CommTest, DeterministicMalformedFrameCorpusDoesNotPoisonChannel) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Server server(channels[1]);
    auto operation = std::make_shared<OneWayOperation>();
    ASSERT_EQ(server.register_operation(42, operation), 0);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    std::mt19937 generator(0x53434f4dU);
    std::uniform_int_distribution<std::size_t> size_distribution(1, 4096);
    std::uniform_int_distribution<unsigned> byte_distribution(0, 255);
    for(unsigned iteration = 0; iteration < 512; ++iteration) {
        std::vector<std::byte> frame(size_distribution(generator));
        for(auto& byte: frame)
            byte = std::byte{static_cast<unsigned char>(byte_distribution(generator))};
        frame[0] = std::byte{'X'};
        ASSERT_EQ(::send(channels[0], frame.data(), frame.size(), MSG_NOSIGNAL),
                  static_cast<ssize_t>(frame.size()));
        std::array<std::byte, 128> response{};
        ASSERT_GT(::recv(channels[0], response.data(), response.size(), 0), 0);
    }
    {
        sx::comm::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        EXPECT_EQ(client.notify(42, "after-corpus"), 0);
        for(unsigned attempt = 0; attempt < 100 && operation->calls.load() == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        EXPECT_EQ(operation->calls.load(), 1U);
        EXPECT_EQ(operation->payload, "after-corpus");
    }
    helper.join();
}

} // namespace
