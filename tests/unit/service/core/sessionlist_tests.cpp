#include <gtest/gtest.h>

#include <service/core/sessionlist.hpp>

#include <chrono>

using namespace std::chrono_literals;

TEST(SessionList, ZeroWorkersCompletesImmediatelyWithEmptyResults) {
    auto text = SessionList::text(0, {});
    auto json = SessionList::json(0, {});

    EXPECT_TRUE(text->complete());
    EXPECT_TRUE(text->wait_for(0ms));
    EXPECT_TRUE(text->text_result().empty());
    EXPECT_EQ(json->json_result(), nlohmann::json::array());
    EXPECT_LT(text->version(), json->version());
}

TEST(SessionList, DuplicateCompletionCannotUnderflowOutstandingWorkers) {
    auto request = SessionList::text(2, {});
    request->prepare_slot(0, "plain acceptor");
    request->prepare_slot(1, "tls acceptor");

    EXPECT_EQ(request->pending_origins(), "plain acceptor, tls acceptor");
    request->complete_empty_slot(0);
    request->complete_empty_slot(0);
    EXPECT_FALSE(request->complete());
    EXPECT_FALSE(request->wait_for(1ms));
    EXPECT_EQ(request->pending_origins(), "tls acceptor");

    request->complete_empty_slot(1);
    EXPECT_TRUE(request->wait_for(1ms));
    EXPECT_TRUE(request->pending_origins().empty());
}

TEST(SessionList, InvalidSlotIsRejectedWithoutChangingCompletion) {
    auto request = SessionList::json(1, {});
    EXPECT_THROW(request->prepare_slot(1, "invalid"), std::out_of_range);
    EXPECT_THROW(request->complete_empty_slot(1), std::out_of_range);
    EXPECT_FALSE(request->complete());
    request->complete_empty_slot(0);
    EXPECT_TRUE(request->complete());
}
