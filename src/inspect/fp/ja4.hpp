/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#ifndef JA4_HPP
#define JA4_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <optional>

#include <openssl/sha.h>
#include <openssl/evp.h>


namespace sx::ja4 {

    namespace util {
        std::vector<uint8_t> hex_string_to_bytes(const std::string &hex);

        std::string hex_string_to_string(const std::string &hex);

        std::optional<std::string> hash_sha256(const std::string_view &input);

        std::string to_dec_2B(size_t w);

        std::string to_hex_string_2B(uint16_t value);

        std::string to_hex_string_1B(uint8_t value);

        bool is_grease_value(uint16_t value);

        static std::optional<std::string> make_ja4(std::string_view input);

        std::vector<std::string_view> split_string_view(std::string_view str, std::string_view delimiter,
                                                        bool first_only,
                                                        bool stop_on_empty);

        std::string to_lower(std::string_view str);
    }

    struct HTTP {
        std::string version = "11";
        std::string cmd;
        std::string lang = "0000";
        bool have_cookie = false;
        bool have_referer = false;

        bool should_parse_cookies = true;
        std::vector<std::pair<std::string_view, std::string_view>> headers;

        std::vector<std::string_view> cookies;
        std::vector<std::string> cookies_values;


        bool process_header(std::string_view header);

        std::string ja4h_a() const;

        std::string ja4h_b_raw() const;

        std::string ja4h_c_raw() const;

        std::string ja4h_d_raw() const;

        std::string ja4h_b() const;

        std::string ja4h_c() const;

        std::string ja4h_d() const;

        std::string ja4h_ab() const;

        std::string ja4h() const;

        std::string ja4h_raw() const;

        void from_buffer(std::string_view data);

    private:
        mutable std::string result_a_raw;
        mutable std::string result_a;
        mutable std::string result_b_raw;
        mutable std::string result_b;
        mutable std::string result_c_raw;
        mutable std::string result_c;
        mutable std::string result_d_raw;
        mutable std::string result_d;

        mutable std::string result_ab;
        mutable std::string result_raw;
        mutable std::string result;

        void clear() const;

    };

    struct TLSServerHello {
        int version;
        bool have_key_share = false;
        uint16_t cipher_suite;
        std::vector<uint16_t> extensions;

        int from_buffer(std::vector<uint8_t> data);

        std::string ver() const;

        std::string exn() const;

        std::string prefix() const;

        std::string ext_string() const;

        std::string const &ja4_raw();

        std::string const &ja4();

    private:
        mutable std::string result_r;
        mutable std::string result;
    };

    struct TLSClientHello {
        uint16_t version = 0;
        bool have_key_share = false;
        bool sni = false;
        std::string alpn = "00";
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        std::vector<uint16_t> sigalgs;
        mutable struct {
            std::string ja4_raw;
            std::string ja4_final;

            void clear() {
                ja4_raw.clear();
                ja4_final.clear();
            }
        } results;

        void clear();

        std::string ver() const;

        std::string di() const;

        std::string cs() const;

        std::string ex() const;

        std::string const &ja4_raw();

        std::string const &ja4();

        // load data from buffer with client hello.
        // NOTE: it assumes ClientHello TLS record, not whole ClientHello packet!
        int from_buffer(const std::vector<uint8_t> &buffer);
    };
}

#endif