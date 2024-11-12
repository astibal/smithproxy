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