#include <iostream>
#include <vector>
#include <cstdint>
#include <optional>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "../engine.hpp"
#include "../inspect/engine/http.hpp"
#include "../inspect/fp/ja4.hpp"

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

} const HTTP_SAMPLES;

using namespace sx::engine::http;
using namespace sx::ja4;

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