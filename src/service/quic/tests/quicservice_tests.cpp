#include <gtest/gtest.h>

#include "service/quic/quicservice.hpp"

#include <chrono>
#include <thread>

namespace quic = sx::quic;

TEST(QuicListenerService, PreparesAndStopsLoopbackListener) {
    quic::listener_service service(0,
                                   "etc/certs/default/srv-cert.pem",
                                   "etc/certs/default/srv-key.pem",
                                   false);

    if (!quic::openssl_quic_available()) {
        EXPECT_FALSE(service.prepare());
        return;
    }

    ASSERT_TRUE(service.prepare()) << service.last_error();
    EXPECT_TRUE(service.ready());

    std::thread runner([&service]() { service.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    service.stop();
    runner.join();
    EXPECT_TRUE(service.last_error().empty()) << service.last_error();
}
