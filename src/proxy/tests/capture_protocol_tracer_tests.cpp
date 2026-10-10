#include <gtest/gtest.h>

#include "proxy/capture_protocol_tracer.hpp"

#include <string>
#include <vector>

namespace {

void collect_row(void* context, std::string_view row) {
    static_cast<std::vector<std::string>*>(context)->emplace_back(row);
}

} // namespace

TEST(CaptureProtocolTracer, EmitsOrderedEscapedCsvRows) {
    std::vector<std::string> rows;
    CaptureProtocolTracer tracer(&rows, collect_row);

    tracer.trace({socle::trace_side::left, socle::trace_component::tls,
                  socle::trace_scope::connection, 0, false,
                  socle::trace_event::handshake_started,
                  socle::trace_status::pending, "cipher=\"x,y\""});
    tracer.trace({socle::trace_side::right, socle::trace_component::tls,
                  socle::trace_scope::connection, 0, false,
                  socle::trace_event::handshake_ready,
                  socle::trace_status::ok, "TLS_AES_256_GCM_SHA384"});

    ASSERT_EQ(rows.size(), 2U);
    EXPECT_EQ(rows[0].find("1,"), 0U);
    EXPECT_NE(rows[0].find(",L,tls,connection,,HANDSHAKE_STARTED,pending,"
                           "\"cipher=\"\"x,y\"\"\""), std::string::npos);
    EXPECT_EQ(rows[1].find("2,"), 0U);
    EXPECT_NE(rows[1].find(",R,tls,connection,,HANDSHAKE_READY,ok,"
                           "TLS_AES_256_GCM_SHA384"), std::string::npos);
}

TEST(CaptureProtocolTracer, AppliesDefaultStreamIdentifier) {
    std::vector<std::string> rows;
    CaptureProtocolTracer tracer(&rows, collect_row, 6);

    tracer.trace({socle::trace_side::proxy, socle::trace_component::stream,
                  socle::trace_scope::stream, 0, false,
                  socle::trace_event::first_data, socle::trace_status::info, {}});

    ASSERT_EQ(rows.size(), 1U);
    EXPECT_NE(rows[0].find(",P,stream,stream,6,FIRST_DATA,info,"),
              std::string::npos);
    EXPECT_FALSE(CaptureProtocolTracer::encode_block(rows[0]).empty());
}
