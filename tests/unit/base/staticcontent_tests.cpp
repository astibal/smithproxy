#include <gtest/gtest.h>

#include <staticcontent.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

TEST(StaticContent, MissingTemplateSetFailsWithoutPublishingPartialState) {
    auto directory = std::string("/tmp/smithproxy-no-such-template-set/");
    EXPECT_FALSE(html()->load_files(directory));
    EXPECT_EQ(html()->get("test"), nullptr);
    EXPECT_TRUE(html()->render_msg_html_page("title", "meta", "body").empty());
}

TEST(StaticContent, LoadsAndRendersCompleteTemplateSet) {
    std::string pattern = "/tmp/smithproxy-static-content-XXXXXX";
    std::vector<char> storage(pattern.begin(), pattern.end());
    storage.push_back('\0');
    auto* created = ::mkdtemp(storage.data());
    ASSERT_NE(created, nullptr);
    std::filesystem::path root(created);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::filesystem::remove_all(path); }
    } cleanup{root};

    std::ofstream(root / "test.txt") << "ready";
    std::ofstream(root / "html_img_warning.txt") << "warning";
    std::ofstream(root / "html_page.txt")
        << "{{ title }}|{{ meta }}|{{ message }}|{{ window_width }}";
    std::ofstream(root / "tls_replacement.txt")
        << "TLS|{{ target }}|{{ reasons }}|{{ action }}";
    auto directory = root.string() + "/";

    ASSERT_TRUE(html()->load_files(directory));
    EXPECT_EQ(html()->render_noargs("test"), "ready");
    EXPECT_EQ(html()->render_noargs("missing"), "");
    EXPECT_EQ(html()->render_msg_html_page("caption", "refresh", "content", "700px"),
              "caption|refresh|content|700px");
    EXPECT_EQ(html()->render_tls_replacement(
                  "example.test", "bad certificate", "override"),
              "TLS|example.test|bad certificate|override");

    auto const response = html()->render_server_response("body", 403);
    EXPECT_NE(response.find("HTTP/1.1 403 Forbidden\r\n"), std::string::npos);
    EXPECT_NE(response.find("Content-Type: text/html; charset=utf-8\r\n"), std::string::npos);
    EXPECT_NE(response.find("Cache-Control: no-store\r\n"), std::string::npos);
    EXPECT_NE(response.find("Connection: close\r\n"), std::string::npos);
    EXPECT_NE(response.find("Content-Length: 4\r\n"), std::string::npos);
    EXPECT_EQ(response.substr(response.find("\r\n\r\n") + 4), "body");

    auto const head = html()->render_server_response("body", 403, true);
    EXPECT_NE(head.find("HTTP/1.1 403 Forbidden\r\n"), std::string::npos);
    EXPECT_NE(head.find("Content-Length: 4\r\n"), std::string::npos);
    EXPECT_EQ(head.substr(head.find("\r\n\r\n") + 4), "");

    EXPECT_NE(html()->render_server_response({}, 500).find(
                  "HTTP/1.1 500 Internal Server Error\r\n"), std::string::npos);
    EXPECT_NE(html()->render_server_response({}, 799).find(
                  "HTTP/1.1 799 Unknown\r\n"), std::string::npos);

    ASSERT_TRUE(std::filesystem::remove(root / "tls_replacement.txt"));
    ASSERT_NO_THROW(std::filesystem::create_symlink(
        root / "test.txt", root / "tls_replacement.txt"));
    EXPECT_FALSE(html()->load_files(directory));
    EXPECT_EQ(html()->render_tls_replacement(
                  "still", "using", "previous"),
              "TLS|still|using|previous");
}

}  // namespace
