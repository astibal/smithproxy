#include <gtest/gtest.h>

#include <service/netservice.hpp>

#include <memory>

namespace {

class FailingCom {
public:
    void nonlocal_dst(bool) {}
    void unblock(int) {}
    void set_monitor(int) {}

    template<typename Handler>
    void set_poll_handler(int, Handler*) {}
};

class FailingListener {
public:
    FailingListener(std::shared_ptr<FdQueue>, FailingCom* com, proxyType)
        : com_(com) {}

    FailingCom* com() { return com_.get(); }
    void worker_count_preference(int) {}
    unsigned int core_multiplier() const { return 1; }
    int bind(unsigned short, char) { return -1; }
    bool listen(int, char) { return false; }

private:
    std::unique_ptr<FailingCom> com_;
};

TEST(NetworkServiceFactoryTest, FailedBindIsRejectedBeforeDescriptorRegistration) {
    {
        auto lock = std::unique_lock(locks::fd().lock_db_lock());
        locks::fd().lock_db().erase(-1);
    }

    EXPECT_THROW((NetworkServiceFactory::prepare_listener<FailingListener, FailingCom>(
            443, "failing-test-listener", 1, proxyType::proxy())), sx::netservice_cannot_bind);
    EXPECT_EQ(locks::fd().lock(-1), nullptr);
}

TEST(NetworkServiceFactoryTest, DisabledListenerDoesNotConstructOrRegisterAnything) {
    auto listeners = NetworkServiceFactory::prepare_listener<FailingListener, FailingCom>(
            443, "disabled-test-listener", -1, proxyType::proxy());
    EXPECT_TRUE(listeners.empty());
    EXPECT_EQ(locks::fd().lock(-1), nullptr);
}

} // namespace
