#include <iostream>
#include <array>
#include <vector>
#include <cstdint>
#include <optional>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "../engine.hpp"
#include "../inspect/engine/http.hpp"
#include "../inspect/fp/ja4.hpp"
#include <ext/hpack/hpack.hpp>

#include <gtest/gtest.h>

struct sample {
    std::string sample;
    std::string r_host;
    std::string r_method;
    std::string r_uri;
};

struct {
    std::string get1 =
        "GET /some/path HTTP/1.1\r\n"
        "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203\r\n"
        "accept-encoding: gzip, deflate, br\r\n"
        "Cookie: some-cookie\r\n"
        "Host: 123.123.123.123\r\n"
        "Connection: close\r\n"
        "\r\n";

    std::string post1 =
        "POST /some/login HTTP/1.1\r\n"
        "Host: 123.123.123.123\n"
        "Sec-Ch-Ua: \"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"\r\n"
        "Sec-Ch-Ua-Mobile: ?0\r\n"
        "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Priority: u=0, i\r\n"
        "Connection: close\r\n"
        "Content-Length: 53\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "par1=1&username=tstman&par11=&credential=Password1%21";

        const std::string raw_http_1 = "474554202f20485454502f312e310d0a486f73743a20332e3132392e37302e31350d0a557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b20496e7465726e65744d6561737572656d656e742f312e303b202b68747470733a2f2f696e7465726e65742d6d6561737572656d656e742e636f6d2f290d0a436f6e6e656374696f6e3a20636c6f73650d0a4163636570743a202a2f2a0d0a4163636570742d456e636f64696e673a20677a69700d0a0d0a";
        const char* JA4H_r_1 = "ge11nn050000_Host,User-Agent,Connection,Accept,Accept-Encoding__";
        const char* JA4H_1 = "ge11nn050000_845398f9f2c0_000000000000_000000000000";

        const std::string raw_http_2 = "504f5354202f72656d6f74652f6c6f67696e636865636b20485454502f312e310d0a486f73743a20332e3132392e37302e31350d0a4163636570743a202a2f2a0d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557365722d4167656e743a20707974686f6e2d68747470782f302e32372e320d0a436f6e74656e742d4c656e6774683a2034320d0a436f6e74656e742d547970653a206170706c69636174696f6e2f782d7777772d666f726d2d75726c656e636f6465640d0a0d0a";
        const char* JA4H_r_2 = "po11nn070000_Host,Accept,Accept-Encoding,Connection,User-Agent,Content-Length,Content-Type__";
        const char* JA4H_2 = "po11nn070000_429be317aafe_000000000000_000000000000";

        const std::string raw_http_3 = "474554202f20485454502f312e310d0a486f73743a206c6f63616c686f73743a383030300d0a557365722d4167656e743a206375726c2f382e312e320d0a4163636570743a202a2f2a0d0a526566657265723a2068747470733a2f2f66616b652e6578616d706c650d0a436f6f6b69653a2079756d6d795f636f6f6b69653d63686f636f3b2074617374795f636f6f6b69653d737472617762657272790d0a4163636570742d4c616e67756167653a2064612c20656e2d47423b713d302e382c20656e3b713d302e370d0a0d0a";
        const char* JA4H_r_3 = "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_tasty_cookie,yummy_cookie_tasty_cookie=strawberry,yummy_cookie=choco";
        const char* JA4H_3 = "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442";

        const std::string cookie1 = "GET /socket.io/1/websocket/a4ed08e8bdd5860-4c7c773809d08918?sr=RU4AAPsgsB6hsEG29EqDnVO_UUy_T8uFRvOpiExD3gtRAMNPqsn0NYKhmA7_BpdNH93WG2w5NSakd5hpgg1ItbwFjQpZI14BkUofLWUvfgMzReWKpCY&issuer=prod-2&sp=connect&se=1731783638678&st=1731231714678&sig=DdPT0f2rZFfcHU_yo6e-HyjM4T5AAFoZdE8MBejpV2A&v=v4&tc={\"cv\":\"2024.04.01.1\",\"ua\":\"TeamsCDL\",\"hr\":\"\",\"v\":\"27/1.0.0.2024101502\"}&timeout=40&auth=true&epid=9f1ee57c-e3b5-44aa-80d5-b3e8790b41f3&userActivity={\"state\":\"active\",\"cv\":\"1BOskXVyJDCrCpIoleijMA.1\"}&ccid=DnVO_UUy_Tw&cor_id=64b0c3df-cc8e-4f38-a8f1-f856aba042a7&con_num=1731232014533_34 HTTP/1.1\r\n"
                                    "Host: pub-ent-plce-05-t.trouter.teams.microsoft.com\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Pragma: no-cache\r\n"
                                    "Cache-Control: no-cache\r\n"
                                    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) MicrosoftTeams-Preview/1.5.00.23861 Chrome/85.0.4183.121 Electron/10.4.7 Safari/537.36\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Origin: https://teams.microsoft.com\r\n"
                                    "Sec-WebSocket-Version: 13\r\n"
                                    "Accept-Encoding: gzip, deflate, br\r\n"
                                    "Accept-Language: en-US\r\n"
                                    "Cookie: MC1=GUID=36e492f393964b65847bcc452818c5a5&HASH=36e4&LV=202404&V=4&LU=1713276371377; platformid_asm=41; skypetoken_asm=eyJhbGciOiJSUzI1NiIsImtpZCI6IjExRkNCRjhEQzBFRTMzQUY3QkIwQTE3OUUzNjI0RUNBNjk1ODE2NjQiLCJ4NXQiOiJFZnlfamNEdU02OTdzS0Y1NDJKT3ltbFlGbVEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3MzEyNzkzOTYsImV4cCI6MTczMTI4NzE2OCwic2t5cGVpZCI6Im9yZ2lkOmM3MmQ2MTQ2LWI3OWQtNDg5MC05NmFkLWQzYWI3MDRhM2VhZCIsInNjcCI6NzgwLCJjc2kiOiIxNzMxMjc5MDk2IiwidGlkIjoiMmMzNmM0NzgtM2QwMC00NTJmLTg1MzUtNDgzOTZmNWYwMWYwIiwicmduIjoiYW1lciIsImFhZF91dGkiOiJFOE9CS3R4R3ZVT2VpMHppaTFFR0FBIiwiYWFkX2lhdCI6MTczMTI3OTA5NiwiYWFkX2FwcGlkIjoiNWUzY2U2YzAtMmIxZi00Mjg1LThkNGItNzVlZTc4Nzg3MzQ2IiwiYWFkX3BmdCI6IjJxMVp5VkxKU01sVFNVWElDMHVrR1ZhRk9Gb2JCSm1HZXFhYUdYcW5obnJuQmlWVlZSb2xtVVFXaC1iby1rYzdoeFZWbWtSVWh4ZWxBSGM1UW5TNUEyamdnMGR2RU5hM1N5Uy13MU5pNUpDdXlPTkU0TWpjajBOVFZBS2pDbFlDS1dnQXxmVkpkVDlzd0ZQMHJLS19VeFZfeFI2UkpTd3NGMWhZb29XVXdUU2lPSFVocG14SW5wWFRhZjk5TmhDYnRaWG54OGZFNTV6clg5MWN3Q0tJZ0pVRXZHQUlvdkNjbk5HTWk0MUloWmpGR1BLUTVVaUVMRVZkTWl6ek1NY254Q1JqT2dnajNnbEVRRWNrSWxScHIwUXZPUDdkS0VxRjZ3YWJUWEVKMFctSUMxamlaeGZSRVBjVHcxYk8zNmU2d3hNY1haR3VrZnp6ZURldXAyNzN6dVQ4X1pNM2stdnF5VElZMGUwbnhGN0NQZy1nSDVQenNCWk11OWdyaU1QQmxWeE1yTGdVRGVndjA4Qkg0SllDa0xreTZnczFyVzN2bFBFQVBzUEd1QW1nQjBoVFRTS3BVUmdwakhHa1NSUlNPWnAtR283OFI5OEJra2xwQnVFQkdhZ3N0MFJocGtWcGtXV29rNWlsenFRV3BhMHNqZ2tKRUNTSmFZSTZWRmdDWllreUJUUUViU3EwNVZ3cHhyYVNVR256cnRsTVlNd28zaVVfMVVOQ3pFT2kwcGZ0eDhocTc2WXhPNGxoUDhQM29hdjRjR3FJR2FwVHJVYmIzazRFZHZGMS1uSHE3cUJMSnRfSDBiQnZIZmZEZnR2X1MxQzlsVlJ6U3VpZzNfVnU0NTMxVjFPN28xajNfUzdTdGVTcldXMWY1Y3RPcElhR0JoRnpueG1KQmtlRXVRNXdZZzR5V0JpbXNRNjJJekpYaklGMkFkTjJjai1oNFUzekxjczBYaE16RjZHTmNIVzcyVHgtenhkM0tIcEpsYy1QdHczSThCOGNPSFBNRXdQZnVYUl9ha2ZSZDE3X21aVlVYRzFlanh2ZXpjZzJhMVg5UEg3c0UwX1dyblkyN2RtYmdyWEtUYzR1WXl6WGlRbW1rQ0dkSUNrTTBkeW9Nc1c3SGFyXzJUNFd0WEZ1Q0hCRWVfUDREfEg1RGFqcllIbTZTSm5XX3ZYdW54UTNuQVJmaWVTbnQ5ZDhuQkJQdUlCb2FYVmFBUkRrNmo1RC1jaTJhRXVzZUpoUWlZNEtWcS1EdmZoZDh1VEl0Z2tzZEMzdE12a3h5eVo1VGNKaXV3MWtXeElQdVFFZGZVSFU3TlJZaHZycUxncTVjbFh6ajRROVYyVEh1bWJpNVRxQnFoc21MWW1CZ3I0dkVMb3Y1ZlVWUjRLNU53VmNWRG9KM2ltWWRRU3FjRWU1aXRaSUJfaW5QdHpJbXJ4LWhYZEdldlBSZlVDS21uQUhYMUF4aGZFLU0tT0gxb3h0bHA0T3J0YkVueGxORjNXdlRwTF9xMmZRZmNkcjhOZmpUZ3BianhEVHd1NEZKY0VENWVDQVZwVmhTYVRqaU9oM1BleW9nb1Rfd2ZhbGlWOWhYTzhjUEJJRmxkQlM0S1cxZHowdyIsImFjY3QiOjB9.HT74XD49JJWCJDln9NaEfI5LJ8khL4kQUSUJHxTFX9KdNvkHE25CmHqicVR38mIrLI7EygNF2Me13ajtSuekHV6RfrFuBKdrMypdt7z2INMsYzTdH1eN5Cq622fOb13zb4z5taQGftRzVKn3q3yJUZtaEX9us_pFvBUSvN25eJ6Q2jxQyCeBxqw0wOUKe6yoLWPTNi5N-_WG6hyNFXZLP9rJVOtd9YTDUWIjGPUC_mmGQXga0tUfI2YcfA8ARe-uiGt8RCi_gB3YSikfKwk2VUwNzfAmGC1NjiVEDtpuKguHVSCRnirsgcIRWNBL2mSA6kpdLS_atYmslvRX0t13Zg\r\n"
                                    "Sec-WebSocket-Key: 7RvtPgk Klxsq8mCOOTpKg==\r\n"
                                    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits";
        const std::string  raw_http_4 = "504f5354202f72656d6f74652f6c6f67696e636865636b20485454502f312e310d0a486f73743a203130392e3233332e37352e32320d0a4163636570743a202a2f2a0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b207836343b2072763a38392e3029204765636b6f2f32303130303130312046697265666f782f38392e300d0a436f6e74656e742d547970653a20746578742f706c61696e3b636861727365743d5554462d380d0a436f6e74656e742d4c656e6774683a2036330d0a0d0a";
        const char* JA4H_r_4 = "po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length__";
        const char* JA4H_4 = "po11nn050000_530ceba2075f_000000000000_000000000000";

} const HTTP_SAMPLES;

using namespace sx::engine::http;
using namespace sx::ja4;

namespace sx::engine::http::v2 {
    const char* frame_type_str(uint8_t type);
    std::size_t find_magic(buffer& frame);
    std::optional<uint32_t> find_frame_sz(buffer const& frame);
    void process_header_entry(EngineCtx& ctx, socle::side_t side,
                              std::shared_ptr<app_HttpRequest> const& app_data,
                              long stream_id, uint8_t flags, buffer const& data,
                              std::string const& header, std::string const& value);
    void process_headers(EngineCtx& ctx, socle::side_t side, long stream_id,
                         uint8_t flags, buffer const& data);
    void process_data(EngineCtx& ctx, socle::side_t side, long stream_id,
                      uint8_t flags, buffer const& data);
    void process_ping(EngineCtx& ctx, socle::side_t side, long stream_id,
                      uint8_t flags, buffer const& data);
    void process_other(EngineCtx& ctx, socle::side_t side, long stream_id,
                       uint8_t flags, buffer const& data);
    std::size_t process_frame(EngineCtx& ctx, socle::side_t side, buffer& frame);
    std::size_t load_prev_state(EngineCtx& ctx, std::size_t absolute_index);
    void save_state(EngineCtx& ctx, std::size_t absolute_index, std::size_t processed);
}

std::shared_ptr<app_HttpRequest> parse(std::string data) {
    sx::engine::EngineCtx ctx;

    buffer b;
    b.assign(data.data(), data.size());
    sx::engine::http::v1::parse_request(ctx, &b);

    HTTP fp;
    fp.from_buffer(b.string_view());
    std::cout << fp.ja4h_ab() << "\n";

    return std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
}


auto test = [] {

    std::shared_ptr<app_HttpRequest> ret;

    ret = parse(HTTP_SAMPLES.get1);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ret->http_data.uri == "/some/path");
    ASSERT_TRUE(ret->http_data.method == "GET");
    //std::cout << ret->to_string(iINF) << "\n";


    ret = parse(HTTP_SAMPLES.post1);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ret->http_data.uri == "/some/login");
    ASSERT_TRUE(ret->http_data.method == "POST");
    //std::cout << ret->to_string(iINF) << "\n";

    HTTP h1;
    h1.version = "11";
    h1.from_buffer(util::hex_string_to_string(HTTP_SAMPLES.raw_http_1));
    std::cout << "h1 my: " << h1.ja4h() << "\n";
    std::cout << "h1   : " << HTTP_SAMPLES.JA4H_1 << "\n";

    HTTP h2;
    h2.version = "11";
    h2.from_buffer(util::hex_string_to_string(HTTP_SAMPLES.raw_http_2));
    std::cout << "h2 my: " << h2.ja4h() << "\n";
    std::cout << "h2   : " << HTTP_SAMPLES.JA4H_2 << "\n";

    HTTP h3;
    h3.version = "11";
    h3.from_buffer(util::hex_string_to_string(HTTP_SAMPLES.raw_http_3));
    std::cout << "h3   my: " << h3.ja4h() << "\n";
    std::cout << "h3     : " << HTTP_SAMPLES.JA4H_3 << "\n";
    std::cout << "h3 r my: " << h3.ja4h_raw() << "\n";
    std::cout << "h3 r   : " << HTTP_SAMPLES.JA4H_r_3 << "\n";

    HTTP h4;
    h4.version = "11";
    h4.from_buffer(HTTP_SAMPLES.cookie1);
    std::cout << "h4 my: " << h4.ja4h() << "\n";

    HTTP h5;
    h5.version = "11";
    h5.from_buffer(util::hex_string_to_string(HTTP_SAMPLES.raw_http_4));
    std::cout << "h5   my: " << h5.ja4h() << "\n";
    std::cout << "h5     : " << HTTP_SAMPLES.JA4H_4 << "\n";
    ASSERT_TRUE(h5.ja4h() == HTTP_SAMPLES.JA4H_4);

    std::cout << "h5 r my: " << h5.ja4h_raw() << "\n";
    std::cout << "h5 r   : " << HTTP_SAMPLES.JA4H_r_4 << "\n";
};

TEST(HTTP1, trivial) {
    test();
}

TEST(HTTP1, benchmark) {

    const size_t repetitions = 100000;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < repetitions; ++i) {
        test();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Test ran " << repetitions << " times in " << duration << " ms.\n";
}

TEST(HTTP1, sample1) {
    test();
}

TEST(HTTP1, ParsesMethodsParametersHeadersAndInvalidInput) {
    sx::engine::EngineCtx ctx;
    EXPECT_TRUE(v1::find_method(ctx, "PATCH /items/42?dry=yes HTTP/1.1\r\n"));
    auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
    ASSERT_TRUE(app);
    EXPECT_EQ(app->http_data.method, "PATCH");
    EXPECT_EQ(app->http_data.uri, "/items/42");
    EXPECT_EQ(app->http_data.params, "dry=yes");

    EXPECT_TRUE(v1::find_host(ctx, "Host: example.test:8443\r\n"));
    EXPECT_EQ(app->http_data.host, "example.test:8443");
    EXPECT_TRUE(v1::find_referrer(ctx, "Referer: https://ref.example/path\r\n"));
    EXPECT_EQ(app->http_data.referer, "https://ref.example/path");

    EXPECT_FALSE(v1::find_method(ctx, "BREW /coffee HTTP/1.1\r\n"));
    EXPECT_FALSE(v1::find_host(ctx, "host: lowercase.example\r\n"));
    EXPECT_FALSE(v1::find_referrer(ctx, "referrer: misspelled\r\n"));
}

TEST(HTTP1, ApplicationDataMaintainsHistoryAndPresentation) {
    app_HttpRequest app;
    app.version = app_HttpRequest::HTTP_VER::HTTP1_1;
    app.http_data = {
        .host = "first.example",
        .uri = "/one",
        .method = "GET",
        .params = "a=1",
        .referer = "https://ref.example/",
        .proto = "https://",
        .sub_proto = "dns",
        .ja4h = "fingerprint-one",
    };
    app.mark_populated();
    EXPECT_EQ(app.protocol(), "http1.1/dns");
    EXPECT_EQ(app.request(), "https://first.example/one?a=1");
    EXPECT_EQ(app.original_request(), "https://ref.example/");
    EXPECT_NE(app.to_string(iDEB).find("fingerprint-one"), std::string::npos);

    app.next();
    EXPECT_FALSE(app.populated());
    EXPECT_TRUE(app.http_data.host.empty());
    app.http_data.proto = "http://";
    app.http_data.host = "second.example";
    app.http_data.uri = "/two";
    app.http_data.ja4h = "fingerprint-two";

    auto const requests = app.requests_all();
    ASSERT_EQ(requests.size(), 2U);
    EXPECT_EQ(requests[0], "http://second.example/two");
    EXPECT_EQ(requests[1], "https://first.example/one?a=1");
    auto const fingerprints = app.custom_list();
    ASSERT_EQ(fingerprints.size(), 2U);
    EXPECT_EQ(fingerprints[0], "fingerprint-two");
    EXPECT_EQ(fingerprints[1], "fingerprint-one");
    EXPECT_EQ(app.custom_list_name(), "ja4h");
}

TEST(HTTP2, StreamHeadersDeriveHostnameAndRegistrableSuffix) {
    v2::Http2Stream stream;
    EXPECT_FALSE(stream.request_header(":authority").has_value());
    EXPECT_FALSE(stream.domain().has_value());
    stream.request_headers_[":authority"] = {"api.service.example"};
    stream.request_headers_[":path"] = {"/old", "/current"};
    EXPECT_EQ(stream.request_header(":path"), "/current");
    EXPECT_EQ(stream.domain(), "example.service");
    EXPECT_EQ(stream.hostname(), "api.service.example");
    EXPECT_FALSE(stream.response_header(":status").has_value());
}

TEST(HTTP2, FrameHelpersHandleKnownUnknownAndIncompleteFrames) {
    EXPECT_STREQ(v2::frame_type_str(0), "data");
    EXPECT_STREQ(v2::frame_type_str(1), "headers");
    EXPECT_STREQ(v2::frame_type_str(2), "priority");
    EXPECT_STREQ(v2::frame_type_str(3), "rst-stream");
    EXPECT_STREQ(v2::frame_type_str(4), "settings");
    EXPECT_STREQ(v2::frame_type_str(5), "push-promise");
    EXPECT_STREQ(v2::frame_type_str(6), "ping");
    EXPECT_STREQ(v2::frame_type_str(7), "goaway");
    EXPECT_STREQ(v2::frame_type_str(8), "window-update");
    EXPECT_STREQ(v2::frame_type_str(9), "continuation");
    EXPECT_STREQ(v2::frame_type_str(10), "altsvc");
    EXPECT_STREQ(v2::frame_type_str(12), "origin");
    EXPECT_STREQ(v2::frame_type_str(16), "priority-update");
    EXPECT_STREQ(v2::frame_type_str(255), "unknown");

    buffer magic;
    magic.assign(v2::txt::magic, v2::txt::magic_sz);
    EXPECT_EQ(v2::find_magic(magic), v2::txt::magic_sz);
    buffer non_magic;
    std::string const other(v2::txt::magic_sz, 'x');
    non_magic.assign(other.data(), other.size());
    EXPECT_EQ(v2::find_magic(non_magic), 0U);

    buffer short_frame;
    std::array<unsigned char, 3> short_bytes{0, 0, 1};
    short_frame.assign(short_bytes.data(), short_bytes.size());
    EXPECT_EQ(v2::find_frame_sz(short_frame), 0U);

    sx::engine::EngineCtx ctx;
    buffer empty;
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, empty), 0U);
    std::array<unsigned char, 9> zero_settings{0, 0, 0, 4, 0, 0, 0, 0, 0};
    buffer complete;
    complete.assign(zero_settings.data(), zero_settings.size());
    EXPECT_EQ(v2::find_frame_sz(complete), 0U);
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, complete), 9U);
    std::array<unsigned char, 9> incomplete_data{0, 0, 3, 0, 0, 0, 0, 0, 1};
    buffer incomplete;
    incomplete.assign(incomplete_data.data(), incomplete_data.size());
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, incomplete), 0U);
}

TEST(HTTP2, HeaderProcessingTracksBothDirectionsAndDetectsDns) {
    sx::engine::EngineCtx ctx;
    ctx.state_data = std::make_any<v2::Http2Connection>();
    auto app = std::make_shared<app_HttpRequest>();
    buffer empty;

    v2::process_header_entry(ctx, socle::side_t::LEFT, app, 7, 0, empty,
                             ":method", "POST");
    v2::process_header_entry(ctx, socle::side_t::LEFT, app, 7, 0, empty,
                             ":authority", "resolver.example");
    app->properties()[":referer"] = "https://ref.example/";
    v2::process_header_entry(ctx, socle::side_t::LEFT, app, 7, 0, empty,
                             "accept", "application/dns-message");
    v2::process_header_entry(ctx, socle::side_t::LEFT, app, 7, 0, empty,
                             ":path", "/dns-query");
    EXPECT_TRUE(app->populated());
    EXPECT_EQ(app->http_data.method, "POST");
    EXPECT_EQ(app->http_data.host, "resolver.example");
    EXPECT_EQ(app->http_data.uri, "/dns-query");
    EXPECT_EQ(app->http_data.referer, "https://ref.example/");

    v2::process_header_entry(ctx, socle::side_t::RIGHT, app, 7, 0, empty,
                             "content-encoding", "gzip");
    v2::process_header_entry(ctx, socle::side_t::RIGHT, app, 7, 0, empty,
                             ":status", "200");
    auto* connection = std::any_cast<v2::Http2Connection>(&ctx.state_data);
    ASSERT_NE(connection, nullptr);
    auto& stream = connection->streams[7];
    EXPECT_EQ(stream.request_header(":path"), "/dns-query");
    EXPECT_EQ(stream.response_header(":status"), "200");
    EXPECT_EQ(stream.content_encoding_, v2::Http2Stream::content_type_t::GZIP);

    buffer payload;
    payload.assign("body", 4);
    v2::process_data(ctx, socle::side_t::LEFT, 7, 0, payload);
    stream.response_headers_["content-type"] = {"text/plain"};
    stream.sub_app_ = v2::Http2Stream::sub_app_t::DNS;
    v2::process_data(ctx, socle::side_t::RIGHT, 7, 0, payload);
    v2::process_ping(ctx, socle::side_t::LEFT, 0, 0, payload);
    v2::process_other(ctx, socle::side_t::LEFT, 0, 0, empty);
    v2::process_other(ctx, socle::side_t::LEFT, 0, 0, payload);
}

TEST(HTTP2, FrameDispatcherCoversDataHeadersPingPriorityAndIncompleteInput) {
    auto frame = [](uint8_t type, uint8_t flags, uint32_t stream,
                    std::vector<uint8_t> payload) {
        std::vector<uint8_t> bytes {
            static_cast<uint8_t>((payload.size() >> 16) & 0xff),
            static_cast<uint8_t>((payload.size() >> 8) & 0xff),
            static_cast<uint8_t>(payload.size() & 0xff),
            type,
            flags,
            static_cast<uint8_t>((stream >> 24) & 0x7f),
            static_cast<uint8_t>((stream >> 16) & 0xff),
            static_cast<uint8_t>((stream >> 8) & 0xff),
            static_cast<uint8_t>(stream & 0xff),
        };
        bytes.insert(bytes.end(), payload.begin(), payload.end());
        buffer result;
        result.assign(bytes.data(), bytes.size());
        return result;
    };

    sx::engine::EngineCtx ctx;
    ctx.state_data = std::make_any<v2::Http2Connection>();

    auto data = frame(0, 0, 3, {'d', 'a', 't', 'a'});
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, data), data.size());

    HPACK::encoder_t encoder;
    encoder.add(":method", "GET", false);
    encoder.add(":authority", "frame.example", false);
    encoder.add(":path", "/frame", false);
    auto headers = frame(1, 0x04, 3, encoder.data());
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, headers), headers.size());

    auto ping = frame(6, 0, 0, std::vector<uint8_t>(8, 0x42));
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::RIGHT, ping), ping.size());
    auto other = frame(8, 0, 0, {0, 0, 0, 1});
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, other), other.size());

    auto priority_data = frame(0, 0x20, 5, {0, 0, 0, 3, 16, 'x'});
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, priority_data),
              priority_data.size());

    auto incomplete = frame(0, 0, 1, {'x'});
    unsigned char* raw = static_cast<unsigned char*>(incomplete.data());
    raw[2] = 5;
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, incomplete), 0U);
}

TEST(HTTP2, DecodesHpackHeadersWithoutRequiringAttachedOrigin) {
    sx::engine::EngineCtx ctx;
    ctx.state_data = std::make_any<v2::Http2Connection>();
    ctx.options.http.ja4h = true;

    HPACK::encoder_t request;
    request.add(":method", "POST", false);
    request.add(":scheme", "https", false);
    request.add(":authority", "resolver.example", false);
    request.add(":path", "/dns-query", false);
    request.add("accept", "application/dns-message", false);
    buffer request_block;
    request_block.assign(request.data().data(), request.data().size());

    v2::process_headers(ctx, socle::side_t::LEFT, 11, 0, request_block);
    auto app = std::dynamic_pointer_cast<app_HttpRequest>(ctx.application_data);
    ASSERT_NE(app, nullptr);
    EXPECT_EQ(app->version, app_HttpRequest::HTTP_VER::HTTP2);
    EXPECT_EQ(app->http_data.method, "POST");
    EXPECT_EQ(app->http_data.proto, "https://");
    EXPECT_EQ(app->http_data.host, "resolver.example");
    EXPECT_EQ(app->http_data.uri, "/dns-query");
    EXPECT_FALSE(app->http_data.ja4h.empty());

    auto* connection = std::any_cast<v2::Http2Connection>(&ctx.state_data);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->streams[11].sub_app_, v2::Http2Stream::sub_app_t::DNS);

    HPACK::encoder_t response;
    response.add(":status", "200", false);
    response.add("content-encoding", "gzip", false);
    buffer response_block;
    response_block.assign(response.data().data(), response.data().size());
    v2::process_headers(ctx, socle::side_t::RIGHT, 11, 0, response_block);
    EXPECT_EQ(connection->streams[11].response_header(":status"), "200");
    EXPECT_EQ(connection->streams[11].content_encoding_,
              v2::Http2Stream::content_type_t::GZIP);

    buffer empty;
    v2::process_headers(ctx, socle::side_t::LEFT, 11, 0, empty);
    const std::array<unsigned char, 3> malformed {0xff, 0xff, 0xff};
    buffer malformed_block;
    malformed_block.assign(malformed.data(), malformed.size());
    EXPECT_NO_THROW(v2::process_headers(
        ctx, socle::side_t::LEFT, 13, 0, malformed_block));
}

TEST(HTTP2, KeepsHpackDynamicTablesPerConnectionAndDirection) {
    sx::engine::EngineCtx ctx;
    ctx.state_data = std::make_any<v2::Http2Connection>();

    HPACK::encoder_t encoder;
    encoder.add("x-dynamic", "first", false);
    buffer first_block;
    first_block.assign(encoder.data().data(), encoder.data().size());
    v2::process_headers(ctx, socle::side_t::LEFT, 21, 0, first_block);

    const auto previous_size = encoder.data().size();
    encoder.add("x-dynamic", "first", false);
    ASSERT_GT(encoder.data().size(), previous_size);
    buffer indexed_block;
    indexed_block.assign(encoder.data().data() + previous_size,
                         encoder.data().size() - previous_size);
    v2::process_headers(ctx, socle::side_t::LEFT, 23, 0, indexed_block);

    auto* connection = std::any_cast<v2::Http2Connection>(&ctx.state_data);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->streams[21].request_header("x-dynamic"), "first");
    EXPECT_EQ(connection->streams[23].request_header("x-dynamic"), "first");

    // The response direction has its own HPACK context. A request-side
    // dynamic index is invalid there and must not publish partial headers.
    v2::process_headers(ctx, socle::side_t::RIGHT, 23, 0, indexed_block);
    EXPECT_FALSE(connection->streams[23].response_header("x-dynamic").has_value());
}

TEST(HTTP2, ReassemblesContinuationOnlyOnTheMatchingStream) {
    auto frame = [](uint8_t type, uint8_t flags, uint32_t stream,
                    std::vector<uint8_t> payload) {
        std::vector<uint8_t> bytes {
            static_cast<uint8_t>((payload.size() >> 16) & 0xff),
            static_cast<uint8_t>((payload.size() >> 8) & 0xff),
            static_cast<uint8_t>(payload.size() & 0xff), type, flags,
            static_cast<uint8_t>((stream >> 24) & 0x7f),
            static_cast<uint8_t>((stream >> 16) & 0xff),
            static_cast<uint8_t>((stream >> 8) & 0xff),
            static_cast<uint8_t>(stream & 0xff),
        };
        bytes.insert(bytes.end(), payload.begin(), payload.end());
        buffer result;
        result.assign(bytes.data(), bytes.size());
        return result;
    };

    sx::engine::EngineCtx ctx;
    HPACK::encoder_t encoder;
    encoder.add(":authority", "continued.example", false);
    ASSERT_GT(encoder.data().size(), 2u);
    const auto middle = encoder.data().begin() + encoder.data().size() / 2;
    std::vector<uint8_t> first(encoder.data().begin(), middle);
    std::vector<uint8_t> second(middle, encoder.data().end());

    auto headers = frame(1, 0, 31, first);
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, headers), headers.size());
    auto* connection = std::any_cast<v2::Http2Connection>(&ctx.state_data);
    ASSERT_NE(connection, nullptr);
    EXPECT_TRUE(connection->request_headers_pending.active());
    EXPECT_EQ(connection->streams.count(31), 0u);

    auto wrong = frame(9, 0x04, 33, second);
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, wrong), wrong.size());
    EXPECT_FALSE(connection->request_headers_pending.active());
    EXPECT_EQ(connection->streams.count(31), 0u);

    // Any interleaved frame invalidates the unfinished header block in this
    // direction. A later CONTINUATION must not resurrect it.
    headers = frame(1, 0, 31, first);
    v2::process_frame(ctx, socle::side_t::LEFT, headers);
    ASSERT_TRUE(connection->request_headers_pending.active());
    auto interleaved = frame(6, 0, 0, {0});
    v2::process_frame(ctx, socle::side_t::LEFT, interleaved);
    EXPECT_FALSE(connection->request_headers_pending.active());
    auto stale_continuation = frame(9, 0x04, 31, second);
    v2::process_frame(ctx, socle::side_t::LEFT, stale_continuation);
    EXPECT_EQ(connection->streams.count(31), 0u);

    headers = frame(1, 0, 31, first);
    v2::process_frame(ctx, socle::side_t::LEFT, headers);
    auto continuation = frame(9, 0x04, 31, second);
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, continuation), continuation.size());
    EXPECT_FALSE(connection->request_headers_pending.active());
    EXPECT_EQ(connection->streams[31].request_header(":authority"), "continued.example");
}

TEST(HTTP2, RemovesHeadersPaddingBeforeHpackDecode) {
    auto frame = [](uint8_t flags, std::vector<uint8_t> payload) {
        std::vector<uint8_t> bytes {
            static_cast<uint8_t>((payload.size() >> 16) & 0xff),
            static_cast<uint8_t>((payload.size() >> 8) & 0xff),
            static_cast<uint8_t>(payload.size() & 0xff), 1, flags,
            0, 0, 0, 41,
        };
        bytes.insert(bytes.end(), payload.begin(), payload.end());
        buffer result;
        result.assign(bytes.data(), bytes.size());
        return result;
    };

    HPACK::encoder_t encoder;
    encoder.add(":authority", "padded.example", false);
    std::vector<uint8_t> payload{3};
    payload.insert(payload.end(), encoder.data().begin(), encoder.data().end());
    payload.insert(payload.end(), 3, 0);

    sx::engine::EngineCtx ctx;
    auto padded = frame(0x0c, payload); // PADDED | END_HEADERS
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, padded), padded.size());
    auto* connection = std::any_cast<v2::Http2Connection>(&ctx.state_data);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->streams[41].request_header(":authority"), "padded.example");

    auto invalid = frame(0x0c, {10, 0});
    EXPECT_EQ(v2::process_frame(ctx, socle::side_t::LEFT, invalid), invalid.size());
}

TEST(HTTP2, ReplacementResponseUsesH2FramesAndSplitsLargeBodies) {
    std::string body(40000, 'x');
    auto response = v2::make_response(17, body, 403);
    ASSERT_TRUE(response.has_value());

    std::size_t offset = 0;
    std::string rebuilt_body;
    unsigned frame_index = 0;
    while(offset < response->size()) {
        ASSERT_GE(response->size() - offset, 9u);
        auto const byte = [&](std::size_t at) {
            return static_cast<uint8_t>((*response)[offset + at]);
        };
        auto const length = (static_cast<std::size_t>(byte(0)) << 16) |
                            (static_cast<std::size_t>(byte(1)) << 8) |
                            byte(2);
        auto const type = byte(3);
        auto const flags = byte(4);
        auto const stream = (static_cast<uint32_t>(byte(5) & 0x7f) << 24) |
                            (static_cast<uint32_t>(byte(6)) << 16) |
                            (static_cast<uint32_t>(byte(7)) << 8) |
                            byte(8);
        ASSERT_LE(length, 16384u);
        ASSERT_LE(offset + 9 + length, response->size());

        auto const payload = std::string_view(*response).substr(offset + 9, length);
        if(frame_index < 2) {
            EXPECT_EQ(type, 4); // SETTINGS then SETTINGS ACK
            EXPECT_EQ(stream, 0u);
            EXPECT_EQ(length, 0u);
            EXPECT_EQ(flags, frame_index == 0 ? 0x00 : 0x01);
        } else if(frame_index == 2) {
            EXPECT_EQ(type, 1); // HEADERS
            EXPECT_EQ(stream, 17u);
            EXPECT_EQ(flags, 0x04); // END_HEADERS, body follows
            HPACK::decoder_t decoder;
            std::vector<uint8_t> encoded(payload.begin(), payload.end());
            ASSERT_TRUE(decoder.decode(encoded));
            EXPECT_EQ(decoder.headers().at(":status").front(), "403");
            EXPECT_EQ(decoder.headers().at("content-type").front(),
                      "text/html; charset=utf-8");
            EXPECT_EQ(decoder.headers().at("content-length").front(), "40000");
            EXPECT_EQ(decoder.headers().at("cache-control").front(), "no-store");
        } else {
            EXPECT_EQ(type, 0); // DATA
            EXPECT_EQ(stream, 17u);
            rebuilt_body.append(payload);
            EXPECT_EQ((flags & 0x01) != 0, offset + 9 + length == response->size());
        }
        offset += 9 + length;
        ++frame_index;
    }

    EXPECT_EQ(frame_index, 6u); // SETTINGS + ACK + HEADERS + three DATA frames
    EXPECT_EQ(rebuilt_body, body);

    auto empty = v2::make_response(1, {}, 200);
    ASSERT_TRUE(empty.has_value());
    ASSERT_GE(empty->size(), 9u);
    ASSERT_GE(empty->size(), 27u);
    EXPECT_EQ(static_cast<uint8_t>((*empty)[3]), 4u);
    EXPECT_EQ(static_cast<uint8_t>((*empty)[12]), 4u);
    EXPECT_EQ(static_cast<uint8_t>((*empty)[13]), 0x01u);
    EXPECT_EQ(static_cast<uint8_t>((*empty)[21]), 1u);
    EXPECT_EQ(static_cast<uint8_t>((*empty)[22]), 0x05u); // END_HEADERS | END_STREAM

    auto head = v2::make_response(19, body, 403, true);
    ASSERT_TRUE(head.has_value());
    std::size_t head_offset = 0;
    unsigned head_frames = 0;
    while(head_offset < head->size()) {
        ASSERT_GE(head->size() - head_offset, 9u);
        auto const length = (static_cast<std::size_t>(
                                 static_cast<uint8_t>((*head)[head_offset])) << 16) |
                            (static_cast<std::size_t>(
                                 static_cast<uint8_t>((*head)[head_offset + 1])) << 8) |
                            static_cast<uint8_t>((*head)[head_offset + 2]);
        auto const type = static_cast<uint8_t>((*head)[head_offset + 3]);
        if(head_frames == 2) {
            EXPECT_EQ(type, 1u);
            EXPECT_EQ(static_cast<uint8_t>((*head)[head_offset + 4]), 0x05u);
            auto const payload = std::string_view(*head).substr(head_offset + 9, length);
            HPACK::decoder_t decoder;
            std::vector<uint8_t> encoded(payload.begin(), payload.end());
            ASSERT_TRUE(decoder.decode(encoded));
            EXPECT_EQ(decoder.headers().at(":status").front(), "403");
            EXPECT_EQ(decoder.headers().at("content-length").front(), "40000");
        } else {
            EXPECT_EQ(type, 4u);
        }
        head_offset += 9 + length;
        ++head_frames;
    }
    EXPECT_EQ(head_frames, 3u); // SETTINGS + ACK + HEADERS, no DATA for HEAD

    EXPECT_FALSE(v2::make_response(0, body).has_value());
    EXPECT_FALSE(v2::make_response(2, body).has_value());
    EXPECT_FALSE(v2::make_response(0x80000001L, body).has_value());
    EXPECT_FALSE(v2::make_response(1, body, 99).has_value());
}

TEST(HTTP2, ReplacementGoawayIsAConnectionLevelFrame) {
    auto const frame = v2::make_goaway(31, 0x0c, "certificate rejected");
    ASSERT_GE(frame.size(), 17u);
    auto const byte = [&](std::size_t at) { return static_cast<uint8_t>(frame[at]); };
    auto const length = (static_cast<std::size_t>(byte(0)) << 16) |
                        (static_cast<std::size_t>(byte(1)) << 8) | byte(2);
    EXPECT_EQ(length, 8u + std::string_view("certificate rejected").size());
    EXPECT_EQ(byte(3), 7u);
    EXPECT_EQ(byte(4), 0u);
    EXPECT_EQ(byte(5) | byte(6) | byte(7) | byte(8), 0u);
    EXPECT_EQ(byte(12), 31u);
    EXPECT_EQ(byte(16), 0x0cu);
    EXPECT_EQ(std::string_view(frame).substr(17), "certificate rejected");
}

TEST(HTTP2, StateHelpersRejectMissingOriginButPersistState) {
    sx::engine::EngineCtx ctx;
    EXPECT_EQ(v2::load_prev_state(ctx, 4), 0U);
    v2::save_state(ctx, 4, 99);
    auto const saved = std::any_cast<v2::state_data_t>(ctx.state_info);
    EXPECT_EQ(saved.first, 4U);
    EXPECT_EQ(saved.second, 99U);
    EXPECT_EQ(v2::load_prev_state(ctx, 4), 0U);
}

TEST(EngineCtx, SeenDataPolicyDistinguishesSmallGrowingAndNewBlocks) {
    sx::engine::EngineCtx ctx;
    EXPECT_TRUE(ctx.new_data_check(1, 100));
    ctx.update_seen_block(1, 100);
    EXPECT_TRUE(ctx.new_data_check(1, 100));

    ctx.application_data = std::make_shared<sx::engine::CustomApplicationData>("test");
    ctx.application_data->mark_populated();
    ctx.update_seen_block(1, 6000);
    EXPECT_FALSE(ctx.new_data_check(1, 6000));
    EXPECT_TRUE(ctx.new_data_check(2, 10));
    EXPECT_FALSE(ctx.application_data->populated());

    ctx.update_seen_block(2, 6000);
    EXPECT_TRUE(ctx.new_data_check(2, 7000));
    ctx.update_seen_block(2, 7000);
    EXPECT_FALSE(ctx.new_data_check(2, 7000));
}
