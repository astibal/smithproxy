#include "fd_transport.hpp"

#include <cerrno>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

namespace libcli2 {
namespace {

TEST(FdTransport, OwnedSharedDescriptorClosesOnce) {
    int pair[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair), 0);
    const int owned = pair[0];
    { FdTransport transport(FdPair(owned, owned)); }
    errno = 0;
    EXPECT_EQ(::close(owned), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(::close(pair[1]), 0);
}

TEST(FdTransport, BorrowedPairRemainsOpen) {
    int pair[2];
    ASSERT_EQ(::pipe(pair), 0);
    { FdTransport transport(FdPair::borrowed(pair[0], pair[1])); }
    EXPECT_EQ(::close(pair[0]), 0);
    EXPECT_EQ(::close(pair[1]), 0);
}

TEST(FdTransport, MoveAndReleaseTransferOwnership) {
    int pair[2];
    ASSERT_EQ(::pipe(pair), 0);
    FdTransport source(FdPair(pair[0], pair[1]));
    FdTransport destination(std::move(source));
    EXPECT_FALSE(source.valid());
    const FdPair released = destination.release();
    EXPECT_FALSE(destination.valid());
    EXPECT_EQ(::close(released.input), 0);
    EXPECT_EQ(::close(released.output), 0);
}

TEST(FdTransport, ResetClosesOldAndInstallsNewPair) {
    int old_pair[2], new_pair[2];
    ASSERT_EQ(::pipe(old_pair), 0);
    ASSERT_EQ(::pipe(new_pair), 0);
    FdTransport transport(FdPair(old_pair[0], old_pair[1]));
    transport.reset(FdPair(new_pair[0], new_pair[1]));
    errno = 0;
    EXPECT_EQ(::close(old_pair[0]), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(transport.input_fd(), new_pair[0]);
    EXPECT_EQ(transport.output_fd(), new_pair[1]);
}

TEST(FdTransport, ReadsAndWritesSocket) {
    int pair[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair), 0);
    FdTransport transport(FdPair(pair[0], pair[0]));
    constexpr char input[] = "input";
    ASSERT_EQ(::write(pair[1], input, sizeof(input)), static_cast<ssize_t>(sizeof(input)));
    char buffer[sizeof(input)]{};
    EXPECT_EQ(transport.read_some(buffer, sizeof(buffer)), static_cast<ssize_t>(sizeof(buffer)));
    EXPECT_STREQ(buffer, input);
    constexpr char output[] = "output";
    EXPECT_EQ(transport.write_some(output, sizeof(output)), static_cast<ssize_t>(sizeof(output)));
    char output_buffer[sizeof(output)]{};
    ASSERT_EQ(::read(pair[1], output_buffer, sizeof(output_buffer)),
              static_cast<ssize_t>(sizeof(output_buffer)));
    EXPECT_STREQ(output_buffer, output);
    EXPECT_EQ(::close(pair[1]), 0);
}

}  // namespace
}  // namespace libcli2
