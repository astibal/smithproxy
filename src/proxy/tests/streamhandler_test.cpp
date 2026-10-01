#include <gtest/gtest.h>

#include <proxy/streamhandler.hpp>

TEST(StreamHandlerSessionName, ReplacesTcpAndTlsEndpointPrefixes) {
    EXPECT_EQ(sx::session_protocol_names(
                  "MitM|l:tcp_192.0.2.10:1234 <+> r:ssli_198.51.100.20:22", "ssh"),
              "MitM|l:ssh_192.0.2.10:1234 <+> r:ssh_198.51.100.20:22");
}

TEST(StreamHandlerSessionName, ReplacesConnectionLabelPrefixes) {
    EXPECT_EQ(sx::session_protocol_names(
                  "tcp_192.0.2.10:1234+tcp_198.51.100.20:22", "ssh"),
              "ssh_192.0.2.10:1234+ssh_198.51.100.20:22");
}

TEST(StreamHandlerSessionName, DoesNotRewriteHostnameText) {
    EXPECT_EQ(sx::session_protocol_names("tcp_host.tcp_example:22", "ssh"),
              "ssh_host.tcp_example:22");
}
