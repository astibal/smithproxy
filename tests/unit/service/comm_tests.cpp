#include <service/comm.hpp>
#include <service/comm_frame.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstring>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <tests/security/hostile_peer.hpp>

namespace {

TEST(CommFrameTest, VersionOneUsesTheCanonicalNulScPrefix) {
    const auto encoded = sx::comm::wire::encode(42, 0, "payload");
    ASSERT_GE(encoded.size(), sx::comm::wire::header_size);
    EXPECT_EQ(encoded[0], std::byte{0});
    EXPECT_EQ(encoded[1], std::byte{'S'});
    EXPECT_EQ(encoded[2], std::byte{'C'});
    EXPECT_EQ(encoded[3], std::byte{1});

    sx::comm::wire::Header header;
    std::string payload;
    ASSERT_TRUE(sx::comm::wire::decode(encoded, header, payload));
    EXPECT_EQ(header.opcode, 42);
    EXPECT_EQ(header.status, 0);
    EXPECT_EQ(payload, "payload");
}

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

    const auto descriptors_before = socle::test::hostile::open_fd_count();
    const auto corpus = socle::test::hostile::frame_corpus(
        {0x53434f4dU, 512, 4096});
    for(const auto& frame: corpus) {
        ASSERT_EQ(socle::test::hostile::send_and_drain(channels[0], frame),
                  socle::test::hostile::DrainResult::Reply);
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
    const auto descriptors_after = socle::test::hostile::open_fd_count();
    if(descriptors_before != 0 && descriptors_after != 0) {
        EXPECT_EQ(descriptors_after, descriptors_before - 2U);
    }
}

} // namespace

namespace {
struct DebugRecord {
    sx::helper_debug::Service service;
    std::uint64_t id;
    std::string event;
    std::string detail;
};
std::vector<DebugRecord> debug_records;
struct CaptureHelperDebug {
    sx::helper_debug::Sink previous;
    CaptureHelperDebug() {
        debug_records.clear();
        previous = sx::helper_debug::sink.exchange(+[](sx::helper_debug::Service service, int,
                std::uint64_t id, std::string_view event, std::string_view detail) {
            debug_records.push_back({service, id, std::string(event), std::string(detail)});
            errno = EACCES; // The sink must not corrupt a transport failure.
        });
    }
    ~CaptureHelperDebug() { sx::helper_debug::sink.store(previous); }
};

TEST(HelperDebug, CorrelatesTimeoutAndPreservesErrnoWithoutPayload) {
    int channels[2];
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Client client(channels[0], std::chrono::milliseconds(10), sx::helper_debug::Service::files);
    ::close(channels[0]);
    CaptureHelperDebug capture;
    sx::comm::Reply reply;
    EXPECT_EQ(client.request(42, "secret-payload", -1, reply), -1);
    EXPECT_EQ(errno, ETIMEDOUT);
    ASSERT_EQ(debug_records.size(), 3U);
    EXPECT_EQ(debug_records[0].service, sx::helper_debug::Service::files);
    EXPECT_EQ(debug_records[1].event, "send");
    EXPECT_EQ(debug_records[2].event, "receive-error");
    EXPECT_NE(debug_records[2].detail.find("errno=" + std::to_string(ETIMEDOUT)), std::string::npos);
    for(auto const& record : debug_records) {
        EXPECT_EQ(record.id, debug_records[0].id);
        EXPECT_NE(record.id, 0U);
        EXPECT_EQ(record.detail.find("secret"), std::string::npos);
    }
    ::close(channels[1]);
}

TEST(HelperDebug, NotificationReportsSendWithoutInventingReply) {
    int channels[2];
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    sx::comm::Client client(channels[0], std::chrono::milliseconds(10), sx::helper_debug::Service::gre);
    ::close(channels[0]);
    CaptureHelperDebug capture;
    EXPECT_EQ(client.notify(42, "secret-frame"), 0);
    ASSERT_EQ(debug_records.size(), 2U);
    EXPECT_EQ(debug_records[1].event, "notified");
    EXPECT_EQ(debug_records[0].id, debug_records[1].id);
    EXPECT_EQ(debug_records[1].detail.find("secret"), std::string::npos);
    ::close(channels[1]);
}

TEST(HelperDebug, EscapesTerminalControlAndBoundsFields) {
    EXPECT_EQ(sx::helper_debug::field("hello\n\033[31m"), "hello__[31m");
    EXPECT_EQ(sx::helper_debug::field(std::string(1000, 'x')).size(), 163U);
}

TEST(HelperDebug, ThrowingSinkCannotBreakCaller) {
    auto old = sx::helper_debug::sink.exchange(+[](sx::helper_debug::Service, int,
            std::uint64_t, std::string_view, std::string_view) { errno = EINVAL; throw 1; });
    errno = ETIMEDOUT;
    sx::helper_debug::emit(sx::helper_debug::Service::sift, 1, "send");
    EXPECT_EQ(errno, ETIMEDOUT);
    sx::helper_debug::sink.store(old);
}
} // namespace
