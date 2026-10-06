#include <gtest/gtest.h>

#include <utils/tenants.hpp>
#include <service/netservice.hpp>
#include <display.hpp>
#include <buffer.hpp>

// Legacy formatting helpers are externally linked but were never declared in
// display.hpp. Keep the test honest without enlarging their public API.
std::string hex_dump2(const unsigned char*, size_t, unsigned int, unsigned char,
                      bool, unsigned int);
void chr_cstrlit(unsigned char, char*, size_t, bool);

TEST(SxMain, ListenerCountHandlesUnknownHardwareConcurrency) {
    EXPECT_EQ(NetworkServiceFactory::listener_count(0, 1, 0), 1U);
    EXPECT_EQ(NetworkServiceFactory::listener_count(0, 4, 0), 1U);
    EXPECT_EQ(NetworkServiceFactory::listener_count(4, 2, 0), 8U);
    EXPECT_EQ(NetworkServiceFactory::listener_count(0, 4, 3), 3U);
}

TEST(SxMain, TenantConfig) {

    using namespace sx::cfg;

    std::string l1 = " 0 ; default ; 0.0.0.0/0 ;  ::/0";
    std::string l2 = "# 1 ; first ; 1.1.1.1/24 ;     ";
    std::string l3 = "2 ; second ; 2.2.2.2/24 ;";
    std::string l4 = " 3; third;;3:3:3::0/64";

    std::vector<TenantConfig> ret1;
    process_tenant_config_line(l1, ret1);
    process_tenant_config_line(l2, ret1);
    process_tenant_config_line(l3, ret1);
    process_tenant_config_line(l4, ret1);

    std::for_each(ret1.begin(), ret1.end(), [](auto& x) { std::cout << x.to_string() << std::endl; });

    ASSERT_TRUE(ret1.size() == 3);
    ASSERT_TRUE(ret1[0].index == 0);
    ASSERT_TRUE(ret1[0].name == "default");
    ASSERT_TRUE(ret1[0].ipv4 == "0.0.0.0/0");
    ASSERT_TRUE(ret1[0].ipv6 == "::/0");

    ASSERT_TRUE(ret1[1].index == 2);
    ASSERT_TRUE(ret1[1].name == "second");
    ASSERT_TRUE(ret1[1].ipv4 == "2.2.2.2/24");
    ASSERT_TRUE(ret1[1].ipv6 == "");

    ASSERT_TRUE(ret1[2].index == 3);
    ASSERT_TRUE(ret1[2].name == "third");
    ASSERT_TRUE(ret1[2].ipv4 == "");
    ASSERT_TRUE(ret1[2].ipv6 == "3:3:3::0/64");

    ASSERT_TRUE(find_tenant(ret1, "default").value_or(-1) == 0);
    ASSERT_TRUE(not find_tenant(ret1, "some"));
    ASSERT_TRUE(find_tenant(ret1, 3).value_or("") == "third");
    ASSERT_TRUE(not find_tenant(ret1, 5));
}

TEST(Display, LegacyAndCurrentHexDumpsPreserveLayoutAndEscaping) {
    std::vector<unsigned char> bytes(20);
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<unsigned char>(i == 8 ? '%' : 'A' + i);

    auto legacy = hex_dump2(bytes.data(), bytes.size(), 2, '>', true, 0x20);
    EXPECT_NE(legacy.find(">[0020]"), std::string::npos);
    EXPECT_NE(legacy.find("25 "), std::string::npos);
    EXPECT_NE(legacy.find(".JKLMNOP"), std::string::npos);
    EXPECT_NE(legacy.find("\r\n"), std::string::npos);

    buffer data(bytes.data(), bytes.size());
    EXPECT_EQ(hex_dump(&data, 0, 0, false, 0), hex_dump(data, 0, 0, false, 0));
    auto current = hex_dump(data, 1, '<', true, 0x10);
    EXPECT_NE(current.find("<[0010]"), std::string::npos);
    EXPECT_NE(current.find("\r\n"), std::string::npos);

    std::vector<unsigned char> oversized(MAX_HEXDUMP_SIZE + 32, 'x');
    EXPECT_NE(hex_dump(oversized.data(), oversized.size()).find("<data too large>"),
              std::string::npos);
}

TEST(Display, CharacterAndStringEscapingCoversControlAndFormatCharacters) {
    struct Case { unsigned char input; const char* escaped; };
    const Case cases[] = {
        {'\a', "\\a"}, {'\b', "\\b"}, {'\f', "\\f"}, {'\n', "\\n"},
        {'\r', "\\r"}, {'\t', "\\t"}, {'\v', "\\v"}, {'\\', "\\\\"},
        {'\'', "\\'"}, {'\"', "\\\""}, {'?', "\\?"},
    };
    for (auto const& item : cases) {
        char output[8]{};
        chr_cstrlit(item.input, output, sizeof(output), false);
        EXPECT_STREQ(output, item.escaped);
    }
    char output[8]{};
    chr_cstrlit('A', output, sizeof(output), false);
    EXPECT_STREQ(output, "A");
    chr_cstrlit('%', output, sizeof(output), true);
    EXPECT_STREQ(output, "%%");
    chr_cstrlit(1, output, sizeof(output), false);
    EXPECT_STREQ(output, "\\001");
    chr_cstrlit('A', output, 1, false);
    EXPECT_STREQ(output, "");
    chr_cstrlit('\n', output, 2, false);
    EXPECT_STREQ(output, "");
    chr_cstrlit(1, output, 4, false);
    EXPECT_STREQ(output, "");

    std::string all{"\a\b\f\v\\%\n\t\r'\"? \x01", 14};
    auto escaped = escape(all, false, true);
    for (auto const expected : {"\\a", "\\b", "\\f", "\\v", "\\\\",
                                "\\n", "\\t", "\\r", "\\'", "\\\"",
                                "\\?", "\\ ", "\\001"})
        EXPECT_NE(escaped.find(expected), std::string::npos) << expected;
    EXPECT_NE(escape("100% ready", true, false).find("100%% ready"), std::string::npos);
}

TEST(Display, LegacyFormattingBacktraceAndErrorHelpersAreUsable) {
    EXPECT_EQ(string_format_old("%s-%d", "value", 7), "value-7");
    EXPECT_EQ(string_format_old("%0600d", 1).size(), 600U);
    EXPECT_NE(string_error(EINVAL).find("error 22"), std::string::npos);
    errno = ENOENT;
    EXPECT_NE(string_error().find("error 2"), std::string::npos);
    EXPECT_NE(bt(false).find("Backtrace:"), std::string::npos);
    EXPECT_NE(bt(true).find("\rBacktrace:"), std::string::npos);
}
