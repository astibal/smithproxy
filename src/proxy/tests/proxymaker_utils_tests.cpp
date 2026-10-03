#include <gtest/gtest.h>

#include <proxy/proxymaker_utils.hpp>

#include <map>
#include <memory>
#include <vector>

TEST(ProxyMakerUtils, ParsesOnlyCompleteValidSourcePorts) {
    EXPECT_EQ(sx::proxymaker::parse_source_port("1"), 1);
    EXPECT_EQ(sx::proxymaker::parse_source_port("443"), 443);
    EXPECT_EQ(sx::proxymaker::parse_source_port("65535"), 65535);

    EXPECT_FALSE(sx::proxymaker::parse_source_port("").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("0").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("-1").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("65536").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port("443x").has_value());
    EXPECT_FALSE(sx::proxymaker::parse_source_port(" 443").has_value());
}

namespace {

struct FakeProxy;

struct FakeCom {
    std::vector<int> monitored;
    std::map<int, FakeProxy*> handlers;
    void set_monitor(int fd) { monitored.push_back(fd); }
    void set_poll_handler(int fd, FakeProxy* proxy) { handlers[fd] = proxy; }
};

struct FakeHost {
    int fd = -1;
    int connect_result = -1;
    int socket() const { return fd; }
    int connect() { return connect_result; }
};

struct FakeProxy {
    static inline int destructed = 0;
    FakeHost* left = nullptr;
    FakeHost* right = nullptr;
    ~FakeProxy() { ++destructed; }
    FakeHost* first_left() { return left; }
    FakeHost* first_right() { return right; }
};

struct FakeOwner {
    explicit FakeOwner(FakeCom* value) : transport(value) {}
    FakeCom* transport = nullptr;
    std::unique_ptr<FakeProxy> child;
    FakeCom* com() { return transport; }
    void add_proxy(std::unique_ptr<FakeProxy> proxy) { child = std::move(proxy); }
};

} // namespace

TEST(ProxyMakerUtils, RejectsFailedUpstreamBeforeRegisteringHandlers) {
    FakeProxy::destructed = 0;
    FakeCom transport;
    FakeHost left{11, -1};
    FakeHost right{-1, -1};
    FakeOwner owner{&transport};
    auto proxy = std::make_unique<FakeProxy>();
    proxy->left = &left;
    proxy->right = &right;

    EXPECT_FALSE(sx::proxymaker::connect_owned_proxy(&owner, std::move(proxy)));
    EXPECT_NE(proxy, nullptr);
    EXPECT_TRUE(transport.monitored.empty());
    EXPECT_TRUE(transport.handlers.empty());
    EXPECT_EQ(owner.child, nullptr);
    proxy.reset();
    EXPECT_EQ(FakeProxy::destructed, 1);
}

TEST(ProxyMakerUtils, RegistersBothSocketsBeforeTransferringOwnership) {
    FakeProxy::destructed = 0;
    FakeCom transport;
    FakeHost left{11, -1};
    FakeHost right{-1, 12};
    FakeOwner owner{&transport};
    auto proxy = std::make_unique<FakeProxy>();
    auto* identity = proxy.get();
    proxy->left = &left;
    proxy->right = &right;

    EXPECT_TRUE(sx::proxymaker::connect_owned_proxy(&owner, std::move(proxy)));
    ASSERT_NE(owner.child, nullptr);
    EXPECT_EQ(owner.child.get(), identity);
    EXPECT_EQ(transport.monitored, (std::vector<int>{12}));
    EXPECT_EQ(transport.handlers.at(11), identity);
    EXPECT_EQ(transport.handlers.at(12), identity);
    EXPECT_EQ(FakeProxy::destructed, 0);
}
