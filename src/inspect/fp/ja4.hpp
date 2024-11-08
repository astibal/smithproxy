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
        std::vector<uint8_t> hex_string_to_bytes(const std::string &hex) {
            std::vector<uint8_t> bytes;
            bytes.reserve(hex.size());

            for (size_t i = 0; i < hex.length(); i += 2) {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        }

        std::optional<std::string> hash_sha256(const std::string_view &input) {

            if(input.empty()) return std::nullopt;

            unsigned char hash[EVP_MAX_MD_SIZE] {};
            unsigned int hash_len;

            EVP_MD_CTX *context = EVP_MD_CTX_new();
            if (context == nullptr) {
                return std::nullopt;
            }

            if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
                EVP_MD_CTX_free(context);
                return std::nullopt;
            }

            if (EVP_DigestUpdate(context, input.data(), input.size()) != 1) {
                EVP_MD_CTX_free(context);
                return std::nullopt;
            }

            if (EVP_DigestFinal_ex(context, hash, &hash_len) != 1) {
                EVP_MD_CTX_free(context);
                return std::nullopt;
            }

            EVP_MD_CTX_free(context);

            // hexlify
            std::ostringstream ss;
            for (unsigned int i = 0; i < hash_len; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string to_hex_string_2B(uint16_t value) {
            std::stringstream ss;
            ss << std::hex << std::setw(4) << std::setfill('0') << value;
            return ss.str();
        }
        std::string to_hex_string_1B(uint8_t value) {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0') << int(value);
            auto ret = ss.str();
            return ret;
        }


        bool is_grease_value(uint16_t value) {
            return ((value & 0x0F0F) == 0x0A0A);
        }
    }


    inline constexpr std::byte to_byte(int value) noexcept {
        return static_cast<std::byte>(value);
    }

    template<typename T>
    inline constexpr T from_byte(std::byte const& r) noexcept {
        return std::to_integer<T>(r);
    }

    struct TLSServerHello {
        int version;
        bool have_key_share = false;
        uint16_t cipher_suite;
        std::vector<uint16_t> extensions;

        int from_buffer(std::vector<uint8_t> data) {

            size_t offset = 4;
            if(offset >= data.size()) return 1;

            // Parsování verze protokolu TLS
            version = (data[offset] << 8) | data[offset + 1];

            offset += 2;
            if(offset >= data.size()) return 2;

            // skip radnom
            offset += 32;
            if(offset >= data.size()) return 3;


            auto session_id_len = data[offset];

            offset += 1 + session_id_len;
            if(offset >= data.size()) return 4;

            cipher_suite = (data[offset] << 8) | data[offset + 1];

            offset += 2;
            if(offset >= data.size()) return 5;


            auto compression_method = data[offset];
            offset += 1;
            if(offset >= data.size()) return 6;


            // extensions
            if (data.size() > offset) {
                size_t extensions_length = (data[offset] << 8) | data[offset + 1];
                offset += 2;

                size_t processed_length = 0;

                while (processed_length < extensions_length) {
                    uint8_t ext_type = (data[offset] << 8) | data[offset + 1];

                    if(ext_type == 0x33) {
                        // key_share - tls 1.3
                        have_key_share = true;
                    }

                    uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
                    extensions.push_back(ext_type);

                    offset += 4 + ext_len;
                    processed_length += 4 + ext_len;

                    if(offset >= data.size()) return 8;
                }
            }
            else {
                return 7;
            }
            return 0;
        }

        std::string ver() const {
            int v = (version - 0x300) + 9;
            if(have_key_share) {
                v = 13;
            }
            std::stringstream ss;
            ss << v;
            return ss.str();
        }

        std::string exn() const {
            std::stringstream ss;
            auto base = extensions.size();
            ss << std::setw(2) << std::setfill('0') << base;
            return ss.str();
        }

        std::string ja4(bool raw=false) {

            std::stringstream fingerprint;
            // t - tcp / q - quic
            fingerprint << "t" << ver() << exn() << "00" << "_" << util::to_hex_string_2B(cipher_suite) << "_";

            std::stringstream suf;
            for (size_t i = 0; i < extensions.size(); ++i) {
                suf << util::to_hex_string_2B(extensions[i]);
                if (i != extensions.size() - 1) {
                    suf << ",";
                }
            }

            std::string what;
            if(raw) {
                what = suf.str();
            }
            else {
                what = util::hash_sha256(suf.str()).value_or("<error>");
                what = what.substr(0,12);
            }

            return fingerprint.str()+what;
        }
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
            void clear() { ja4_raw.clear(); ja4_final.clear(); }
        } results;

        void clear() {
            version = 0;
            sni = false;
            alpn = "00";
            cipher_suites.clear();
            extensions.clear();
            sigalgs.clear();

            results.clear();
        }

        std::string ver() const {
            int v = (version - 0x300) + 9;

            if(have_key_share) {
                v = 13;
            }

            std::stringstream ss;
            ss << v;
            return ss.str();
        }

        std::string di() const { return (sni ? "d" : "i"); }

        std::string cs() const {
            std::stringstream ss;
            ss << cipher_suites.size();
            return ss.str();
        }

        std::string ex() const {
            std::stringstream ss;
            auto base = extensions.size();

            // add extensions which are skipped in the list, but present in prefix
            if(alpn != "00") base++;
            if(sni) base++;

            ss << base;
            return ss.str();
        }

        std::string ja4_raw() {
            if(! results.ja4_raw.empty()) {
                return results.ja4_raw;
            }

            std::stringstream fingerprint;

            std::sort(cipher_suites.begin(), cipher_suites.end());
            std::sort(extensions.begin(), extensions.end());

            // t - tcp / q - quic
            fingerprint << "t" << ver() << di() << cs() << ex() << alpn << "_";

            // ciphers
            for (size_t i = 0; i < cipher_suites.size(); ++i) {
                fingerprint << util::to_hex_string_2B(cipher_suites[i]);
                if (i != cipher_suites.size() - 1) {
                    fingerprint << ",";
                }
            }
            fingerprint << "_";

            // extensions
            for (size_t i = 0; i < extensions.size(); ++i) {
                fingerprint << util::to_hex_string_2B(extensions[i]);
                if (i != extensions.size() - 1) {
                    fingerprint << ",";
                }
            }
            fingerprint << "_";

            //Signature hash algos
            for (size_t i = 0; i < sigalgs.size(); ++i) {
                fingerprint << util::to_hex_string_2B(sigalgs[i]);
                if (i != sigalgs.size() - 1) {
                    fingerprint << ",";
                }
            }

            results.ja4_raw = fingerprint.str();
            return results.ja4_raw;
        }

        std::string ja4() {
            if(! results.ja4_final.empty())
                return results.ja4_final;

            results.ja4_final = TLSClientHello::make_ja4(ja4_raw()).value_or("<error>");
            return results.ja4_final;
        }

        static std::optional<std::string> make_ja4(std::string const& input) {

            size_t u1 = input.find('_');
            if(u1 == std::string::npos)
                return std::nullopt;

            size_t u2 = input.find('_', u1 + 1);
            if(u2 == std::string::npos)
                return std::nullopt;

            std::string pre = input.substr(0, u1);
            std::string_view cs(input.data() + u1 + 1, u2 - u1 - 1);
            std::string_view ex_sg(input.data() + u2 + 1, input.size() - u2 - 1);


            std::string hash_result1 = util::hash_sha256(cs).value_or("");
            std::string hash_result2 = util::hash_sha256(ex_sg).value_or("");

            // truncate sha256 hashes to 12B
            if(hash_result1.size() >= 12 and hash_result2.size() >= 12) {
                std::string h1 = hash_result1.substr(0, 12);
                std::string h2 = hash_result2.substr(0, 12);

                return pre + "_" + h1 + "_" + h2;
            }
            return std::nullopt;
        }

        enum class parse_status {};


        // load data from buffer with client hello.
        // NOTE: it assumes ClientHello TLS record, not whole ClientHello packet!
        int from_buffer(const std::vector<uint8_t> &buffer) {
            clear();

            size_t offset = 0;

            // skip start
            if (buffer.size() < 5) {
                return 1;
            }

            offset += 4;

            // TLS version
            if (offset + 2 > buffer.size()) {
                return 2;
            }
            version = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;

            // random (32 bytes)
            if (offset + 32 > buffer.size()) {
                return 3;
            }
            offset += 32;

            // session ID length and session ID
            if (offset + 1 > buffer.size()) {
                return 4;
            }
            uint8_t session_id_length = buffer[offset];

            offset += 1;
            if (offset + session_id_length > buffer.size()) {
                return 5;
            }
            offset += session_id_length;

            // ciphers length
            if (offset + 2 > buffer.size()) {
                return 6;
            }
            size_t cipher_suite_length = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;

            // extract ciphers
            if (offset + cipher_suite_length > buffer.size()) {
                return 7;
            }
            for (size_t i = 0; i < cipher_suite_length; i += 2) {
                uint16_t cipher_suite = (buffer[offset + i] << 8) | buffer[offset + i + 1];
                cipher_suites.push_back(cipher_suite);
            }
            offset += cipher_suite_length;

            // skip compression len and compression
            if (offset + 1 > buffer.size()) {
                return 8;
            }
            uint8_t compression_methods_length = buffer[offset];
            offset += 1;
            if (offset + compression_methods_length > buffer.size()) {
                return 9;
            }
            offset += compression_methods_length;

            // extension length
            if (offset + 2 > buffer.size()) {
                return 10;
            }
            size_t extensions_length = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;

            // extract extensions
            if (offset + extensions_length > buffer.size()) {
                return 11;
            }
            for (size_t i = 0; i < extensions_length;) {
                //if (offset + i + 4 > buffer.size()) {
                if (offset + i + 4 > buffer.size()) {
                    return 12;
                }
                uint16_t extension_type = (buffer[offset + i] << 8) | buffer[offset + i + 1];
                uint16_t extension_len = (buffer[offset + i + 2] << 8) | buffer[offset + i + 3];

                if(offset + i + 4 + extension_len > buffer.size()) {
                    return 13;
                }

                if (extension_type == 00 and extension_len > 0) {
                    sni = true;
                } else if (extension_type == 0x10) {
                    // ALPN
                    [[maybe_unused]] uint16_t alpn_len = (buffer[offset + i + 4] << 8) | buffer[offset + i + 5];
                    if (extension_len >= 6) {
                        uint8_t fst_alpn_len = buffer[offset + i + 6];

                        std::string_view fst_alpn((const char*) &buffer[offset + i + 7], fst_alpn_len);
                        //may be tested - i.e. `std::string fst_alpn = { 'x', 0x0a };`
                        if(fst_alpn == "h2") {
                            // explicit h2 support
                            alpn = "h2";
                        }
                        else if(fst_alpn == "http/1.1") {
                            // explicit http/1.1 support as h1
                            alpn = "h1";
                        }
                        else {
                            if(! fst_alpn.empty()) {

                                char fst_val = fst_alpn[0];
                                char snd_val = fst_alpn[0];

                                if(not fst_alpn.empty()) snd_val = fst_alpn[fst_alpn.size() - 1];

                                bool is_alnum_1 = isalnum(fst_val);
                                bool is_alnum_2 = isalnum(snd_val);
                                if( is_alnum_1 and is_alnum_2) {
                                    alpn = fst_val;
                                    alpn += snd_val;
                                }
                                else {
                                    // if any of these two are non-alpha, print first byte and last byte from their hex
                                    alpn = util::to_hex_string_1B(fst_val)[0];
                                    alpn += util::to_hex_string_1B(snd_val)[1];
                                }
                            }
                        }
                    }
                } else if(extension_type == 0x33) {
                    // key_share - tls 1.3
                    have_key_share = true;
                    extensions.push_back(extension_type);

                }
                else if (!util::is_grease_value(extension_type)) {
                    extensions.push_back(extension_type);

                    if (extension_type == 0x000d) {
                        uint16_t hash_len = (buffer[offset + i + 4] << 8) | buffer[offset + i + 5];
                        if (offset + 4 + 2 + hash_len > buffer.size()) {
                            return 14;
                        }
                        for (size_t j = 0; j < hash_len;) {
                            sigalgs.push_back((buffer[offset + i + j + 6] << 8) | buffer[offset + i + j + 7]);
                            j += 2;
                        }
                    }
                }

                i += (extension_len + 4);
            }

            return 0;
        }
    };
}


