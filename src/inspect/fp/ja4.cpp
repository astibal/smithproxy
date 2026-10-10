#include <inspect/fp/ja4.hpp>

namespace sx::ja4 {

    namespace {
        std::string_view trim_ows(std::string_view value) {
            while(!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                value.remove_prefix(1);
            while(!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                value.remove_suffix(1);
            return value;
        }
    }

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
        std::string hex_string_to_string(const std::string &hex) {
            std::string bytes;
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

        std::string to_dec_2B(size_t w) {
            std::stringstream ss;
            ss << std::setw(2) << std::setfill('0') << w;
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

        static std::optional<std::string> make_ja4(std::string_view input) {

            size_t u1 = input.find('_');
            if(u1 == std::string::npos)
                return std::nullopt;

            size_t u2 = input.find('_', u1 + 1);
            if(u2 == std::string::npos)
                return std::nullopt;

            std::string_view pre = input.substr(0, u1);
            std::string_view cs(input.data() + u1 + 1, u2 - u1 - 1);
            std::string_view ex_sg(input.data() + u2 + 1, input.size() - u2 - 1);


            std::string hash_result1 = util::hash_sha256(cs).value_or("");
            std::string hash_result2 = util::hash_sha256(ex_sg).value_or("");

            // truncate sha256 hashes to 12B
            if(hash_result1.size() >= 12 && hash_result2.size() >= 12) {
                std::stringstream ss;
                std::string h1 = hash_result1.substr(0, 12);
                std::string h2 = hash_result2.substr(0, 12);

                ss << pre << "_" << h1 << "_" << h2;
                return ss.str();
            }
            return std::nullopt;
        }

        std::vector<std::string_view> split_string_view(std::string_view str, std::string_view delimiter,
                                                        bool first_only,
                                                        bool stop_on_empty) {
            std::vector<std::string_view> result;
            size_t start = 0;

            while (start < str.size()) {
                size_t end = str.find(delimiter, start);

                if (end == std::string_view::npos) {
                    result.emplace_back(str.substr(start));
                    break;
                }

                const auto part = str.substr(start, end - start);
                if(stop_on_empty and part.empty()) {
                    break;
                }
                result.emplace_back(part);
                start = end + delimiter.size();

                if(first_only and result.size() == 2) break;
            }

            return result;
        }

        std::string to_lower(std::string_view str) {
            std::string lower_str(str);
            std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return lower_str;
        };
    }


    bool HTTP::process_header_pair(std::pair<std::string_view,std::string_view> header_pair) {

        auto locase = util::to_lower(header_pair.first);
        if(locase == "cookie") {
            have_cookie = true;
            if(should_parse_cookies) {
                auto ck = util::split_string_view(header_pair.second, ";", false, true);
                for(auto const& cookie_pair: ck) {
                    auto cs = util::split_string_view(trim_ows(cookie_pair),"=", true, true);
                    if(cs.size() == 2) {
                        const auto name = trim_ows(cs[0]);
                        const auto value = trim_ows(cs[1]);
                        if(name.empty()) continue;
                        cookies.push_back(name);
                        std::stringstream ss;
                        ss << name << "=" << value;
                        cookies_values.push_back(ss.str());
                    }
                }
            }

            return true;
        }
        else if(locase == "referer") {
            have_referer = true;
            return true;
        }
        else if(locase == "accept-language") {
            lang.clear();
            for(auto c: header_pair.second) {
                if(std::isalnum(static_cast<unsigned char>(c))) {
                    lang += c;
                }
                else if (c == ',') {
                    // don't continue into next part
                    break;
                }
                else if(lang.size() >= 4)
                    // we have enough
                    break;
            }
            auto fill = 4 - lang.size();
            for (size_t i = 0; i < fill ; ++i) {
                lang += "0";
            }

            lang = util::to_lower(lang);
        }
        headers.emplace_back(header_pair);
        return true;

    }

    bool HTTP::process_header(std::string_view header) {
        clear();

        // empty cmd implies this was not called
        if(cmd.empty()) {
            cmd = util::to_lower(header.substr(0,2));
        }

        const auto colon = header.find(':');
        if(colon == std::string_view::npos || colon == 0) return false;
        return process_header_pair(
            std::make_pair(header.substr(0, colon), trim_ows(header.substr(colon + 1))));
    }


    std::string HTTP::ja4h_a() const {
        if(! result_a_raw.empty()) return result_a_raw;

        std::stringstream ss;
        auto base_count = headers.size();
        ss << cmd << version << (have_cookie ? 'c' : 'n') << (have_referer ? 'r' : 'n');
        ss << util::to_dec_2B(base_count) << lang;

        result_a_raw = ss.str();
        return result_a_raw;
    }

    std::string HTTP::ja4h_b_raw() const {
        if(! result_b_raw.empty()) return result_b_raw;

        std::stringstream suf;
        for (size_t i = 0; i < headers.size(); ++i) {
            suf << headers[i].first;
            if (i != headers.size() - 1) {
                suf << ",";
            }
        }
        result_b_raw = suf.str();
        return result_b_raw;
    }

    std::string HTTP::ja4h_c_raw() const {
        if(! result_c_raw.empty()) return result_c_raw;

        std::stringstream suf;

        auto cookies_copy = cookies;
        std::sort(cookies_copy.begin(), cookies_copy.end());

        for (size_t i = 0; i < cookies_copy.size(); ++i) {
            suf << cookies_copy[i];
            if (i != cookies_copy.size() - 1) {
                suf << ",";
            }
        }
        result_c_raw = suf.str();
        return result_c_raw;
    }

    std::string HTTP::ja4h_d_raw() const {
        if(! result_d_raw.empty()) return result_d_raw;

        std::stringstream suf;

        auto cookies_copy = cookies_values;
        std::sort(cookies_copy.begin(), cookies_copy.end());

        for (size_t i = 0; i < cookies_copy.size(); ++i) {
            suf << cookies_copy[i];
            if (i != cookies_copy.size() - 1) {
                suf << ",";
            }
        }
        result_d_raw = suf.str();
        return result_d_raw;
    }

    std::string HTTP::ja4h_b() const {
        if(! result_b.empty()) return result_b;

        auto r = ja4h_b_raw();

        result_b  = r.empty() ? "000000000000" : util::hash_sha256(r)->substr(0,12);
        return result_b;
    }

    std::string HTTP::ja4h_c() const {
        if(! result_c.empty()) return result_c;

        auto r = ja4h_c_raw();

        result_c  = r.empty() ? "000000000000" : util::hash_sha256(r)->substr(0,12);
        return result_c;
    }

    std::string HTTP::ja4h_d() const {
        if(! result_d.empty()) return result_d;

        auto r = ja4h_d_raw();

        result_d  = r.empty() ? "000000000000" : util::hash_sha256(r)->substr(0,12);
        return result_d;
    }

    std::string HTTP::ja4h_ab() const {
        if(! result_ab.empty()) return result_ab;

        std::stringstream ss;
        ss << ja4h_a() << "_" << ja4h_b();

        result_ab = ss.str();
        return result_ab;
    };

    std::string HTTP::ja4h() const {
        if(! result.empty()) return result;

        auto a = ja4h_a();
        auto b = ja4h_b();
        auto c = ja4h_c();
        auto d = ja4h_d();

        std::stringstream ss;
        ss << a << "_" << b << "_" << c << "_" << d;

        result = ss.str();
        return result;
    };

    std::string HTTP::ja4h_raw() const {
        if(! result_raw.empty()) return result_raw;

        auto a = ja4h_a();
        auto b = ja4h_b_raw();
        auto c = ja4h_c_raw();
        auto d = ja4h_d_raw();

        std::stringstream ss;
        ss << a << "_" << b << "_" << c << "_" << d;

        result_raw = ss.str();
        return result_raw;
    };

    void HTTP::from_buffer(std::string_view data) {
        cmd.clear();
        lang = "0000";
        have_cookie = false;
        have_referer = false;
        headers.clear();
        cookies.clear();
        cookies_values.clear();
        clear();

        std::size_t offset = 0;
        while(offset < data.size()) {
            auto end = data.find('\n', offset);
            if(end == std::string_view::npos) end = data.size();
            auto header = data.substr(offset, end - offset);
            if(!header.empty() && header.back() == '\r') header.remove_suffix(1);
            if(header.empty()) break;
            process_header(header);
            offset = end < data.size() ? end + 1 : data.size();
        }

        // Parsed fields are views into the caller's buffer. Materialize every
        // public result before returning so an rvalue input cannot leave a
        // delayed fingerprint calculation referring to destroyed storage.
        (void) ja4h_raw();
    }

    void HTTP::clear() const {
        result_a.clear();
        result_a_raw.clear();
        result_a.clear();
        result_b_raw.clear();
        result_b.clear();
        result_c_raw.clear();
        result_c.clear();
        result_d_raw.clear();
        result_d.clear();

        result_ab.clear();
        result_raw.clear();
        result.clear();
    }


    int TLSServerHello::from_buffer(std::vector<uint8_t> data) {
        version = 0;
        have_key_share = false;
        cipher_suite = 0;
        extensions.clear();
        result_r.clear();
        result.clear();

        size_t offset = 4;
        if (offset + 2 > data.size()) return 1;

        // Parsování verze protokolu TLS
        version = (data[offset] << 8) | data[offset + 1];

        offset += 2;

        // skip random
        if (offset + 32 > data.size()) return 2;
        offset += 32;

        if (offset + 1 > data.size()) return 3;
        auto session_id_len = data[offset];

        offset += 1;
        if (offset + session_id_len > data.size()) return 4;
        offset += session_id_len;

        if (offset + 2 > data.size()) return 5;
        cipher_suite = (data[offset] << 8) | data[offset + 1];

        offset += 2;

        if (offset + 1 > data.size()) return 6;
        offset += 1;

        // TLS 1.2 and older may end ServerHello after compression_method.
        if (offset == data.size()) return 0;

        // extensions
        if (offset + 2 > data.size()) return 7;
        size_t extensions_length = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        if (extensions_length != data.size() - offset) return 8;

        std::vector<uint16_t> seen_extensions;
        for (size_t processed_length = 0; processed_length < extensions_length;) {
            if (extensions_length - processed_length < 4) return 9;

            const size_t ext_offset = offset + processed_length;
            uint16_t ext_type = (data[ext_offset] << 8) | data[ext_offset + 1];
            uint16_t ext_len = (data[ext_offset + 2] << 8) | data[ext_offset + 3];
            if (ext_len > extensions_length - processed_length - 4) return 10;
            if (std::find(seen_extensions.begin(), seen_extensions.end(), ext_type)
                != seen_extensions.end()) return 11;
            seen_extensions.push_back(ext_type);

            auto const payload = ext_offset + 4;
            if (ext_type == 0x2b) {
                if (ext_len != 2) return 11;
                auto const selected = static_cast<uint16_t>(
                    (data[payload] << 8) | data[payload + 1]);
                if (util::is_grease_value(selected)) return 11;
                version = selected;
            }
            if(ext_type == 0x33) {
                // key_share - tls 1.3
                // HelloRetryRequest carries only selected_group; an ordinary
                // ServerHello follows it with the length-prefixed key bytes.
                if (ext_len != 2) {
                    if (ext_len < 5) return 11;
                    auto const key_size = static_cast<std::size_t>(
                        (data[payload + 2] << 8) | data[payload + 3]);
                    if (key_size == 0
                        || key_size != static_cast<std::size_t>(ext_len) - 4) return 11;
                }
                have_key_share = true;
            }

            extensions.push_back(ext_type);
            processed_length += 4 + ext_len;
        }
        return 0;
    }

    std::string TLSServerHello::ver() const {
        int v = (version - 0x300) + 9;
        std::stringstream ss;
        ss << v;
        return ss.str();
    }

    std::string TLSServerHello::exn() const {
        std::stringstream ss;
        auto base = extensions.size();
        ss << std::setw(2) << std::setfill('0') << base;
        return ss.str();
    }

    std::string TLSServerHello::prefix() const {
        std::stringstream fingerprint;
        // t - tcp / q - quic

        fingerprint << "t" << ver() << exn() << "00" << "_" << util::to_hex_string_2B(cipher_suite);
        return fingerprint.str();
    }

    std::string TLSServerHello::ext_string() const {

        std::stringstream suf;
        for (size_t i = 0; i < extensions.size(); ++i) {
            suf << util::to_hex_string_2B(extensions[i]);
            if (i != extensions.size() - 1) {
                suf << ",";
            }
        }
        return suf.str();
    };

    std::string const& TLSServerHello::ja4_raw() {
        if(! result_r.empty()) return result_r;

        std::stringstream  ja4r;
        ja4r << prefix() << "_" << ext_string();
        result_r = ja4r.str();
        return result_r;
    }

    std::string const& TLSServerHello::ja4() {
        if(! result.empty()) return result;

        std::stringstream  ja4;
        auto hashed = util::hash_sha256(ext_string()).value_or("<error>");
        hashed = hashed.substr(0,12);

        ja4 << prefix() << "_" << hashed;
        result = ja4.str();
        return result;
    }



    void TLSClientHello::clear() {
        version = 0;
        have_key_share = false;
        sni = false;
        alpn = "00";
        cipher_suites.clear();
        extensions.clear();
        sigalgs.clear();

        results.clear();
    }

    std::string TLSClientHello::ver() const {
        int v = (version - 0x300) + 9;
        std::stringstream ss;
        ss << v;
        return ss.str();
    }

    std::string TLSClientHello::di() const { return ( (sni && ! ignore_sni) ? "d" : "i"); }

    std::string TLSClientHello::cs() const {
        std::stringstream ss;
        ss << cipher_suites.size();
        return ss.str();
    }

    std::string TLSClientHello::ex() const {
        std::stringstream ss;
        auto base = extensions.size();

        // add extensions which are skipped in the list, but present in prefix
        if(alpn != "00") base++;
        if(sni && ! ignore_sni) base++;

        ss << base;
        return ss.str();
    }

    std::string const& TLSClientHello::ja4_raw() {
        if(! results.ja4_raw.empty()) {
            return results.ja4_raw;
        }

        std::stringstream fingerprint;

        std::sort(cipher_suites.begin(), cipher_suites.end());
        std::sort(extensions.begin(), extensions.end());

        // t - tcp / q - quic
        fingerprint << proto << ver() << di() << cs() << ex() << alpn << "_";

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

    std::string const& TLSClientHello::ja4() {
        if(! results.ja4_final.empty())
            return results.ja4_final;

        results.ja4_final = util::make_ja4(ja4_raw()).value_or("<error>");
        return results.ja4_final;
    }

    // load data from buffer with client hello.
    // NOTE: it assumes ClientHello TLS record, not whole ClientHello packet!
    int TLSClientHello::from_buffer(const std::vector<uint8_t> &buffer) {
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
        if ((cipher_suite_length & 1U) != 0 ||
            cipher_suite_length > buffer.size() - offset) {
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
        if (compression_methods_length == 0) return 9;
        offset += 1;
        if (offset + compression_methods_length > buffer.size()) {
            return 9;
        }
        offset += compression_methods_length;

        // Extensions are optional in legacy ClientHello messages. Their
        // length field itself is absent when the message ends here.
        if (offset == buffer.size()) return 0;

        // extension length
        if (offset + 2 > buffer.size()) {
            return 10;
        }
        size_t extensions_length = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        // extract extensions
        if (extensions_length != buffer.size() - offset) {
            return 11;
        }
        std::vector<uint16_t> seen_extensions;
        for (size_t i = 0; i < extensions_length;) {
            //if (offset + i + 4 > buffer.size()) {
            if (i > extensions_length || extensions_length - i < 4) {
                return 12;
            }
            uint16_t extension_type = (buffer[offset + i] << 8) | buffer[offset + i + 1];
            uint16_t extension_len = (buffer[offset + i + 2] << 8) | buffer[offset + i + 3];

            if(extension_len > extensions_length - i - 4) {
                return 13;
            }
            if (std::find(seen_extensions.begin(), seen_extensions.end(), extension_type)
                != seen_extensions.end()) return 14;
            seen_extensions.push_back(extension_type);
            const size_t payload = offset + i + 4;

            if (extension_type == 0x0000) {
                if (extension_len < 5) return 14;
                auto const names_size = static_cast<std::size_t>(
                    (buffer[payload] << 8) | buffer[payload + 1]);
                if (names_size != static_cast<std::size_t>(extension_len) - 2) return 14;
                for (std::size_t cursor = 0; cursor < names_size;) {
                    if (names_size - cursor < 3) return 14;
                    auto const name_type = buffer[payload + 2 + cursor];
                    auto const name_size = static_cast<std::size_t>(
                        (buffer[payload + 3 + cursor] << 8)
                        | buffer[payload + 4 + cursor]);
                    if (name_size == 0 || name_size > names_size - cursor - 3) return 14;
                    (void)name_type;
                    cursor += 3 + name_size;
                }
                sni = true;
            } else if (extension_type == 0x10) {
                // ALPN
                if (extension_len >= 3) {
                    uint16_t alpn_len = (buffer[payload] << 8) | buffer[payload + 1];
                    if (alpn_len != extension_len - 2 || alpn_len < 2) return 14;
                    for (std::size_t cursor = 0; cursor < alpn_len;) {
                        auto const name_size = buffer[payload + 2 + cursor];
                        if (name_size == 0 || name_size > alpn_len - cursor - 1) return 14;
                        cursor += 1 + name_size;
                    }
                    uint8_t fst_alpn_len = buffer[payload + 2];
                    if (fst_alpn_len > alpn_len - 1) return 14;

                    std::string_view fst_alpn((const char*) &buffer[payload + 3], fst_alpn_len);
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

                            const auto fst_val = static_cast<unsigned char>(fst_alpn.front());
                            auto snd_val = fst_val;

                            if(! fst_alpn.empty()) {
                                snd_val = static_cast<unsigned char>(fst_alpn.back());
                            }

                            bool is_alnum_1 = isalnum(fst_val);
                            bool is_alnum_2 = isalnum(snd_val);
                            if( is_alnum_1 && is_alnum_2) {
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
                if (extension_len < 2) return 14;
                auto const shares_size = static_cast<std::size_t>(
                    (buffer[payload] << 8) | buffer[payload + 1]);
                if (shares_size != static_cast<std::size_t>(extension_len) - 2) return 14;
                for (std::size_t cursor = 0; cursor < shares_size;) {
                    if (shares_size - cursor < 4) return 14;
                    auto const key_size = static_cast<std::size_t>(
                        (buffer[payload + 4 + cursor] << 8)
                        | buffer[payload + 5 + cursor]);
                    if (key_size == 0 || key_size > shares_size - cursor - 4) return 14;
                    cursor += 4 + key_size;
                }
                have_key_share = true;
                extensions.push_back(extension_type);

            }
            else if (!util::is_grease_value(extension_type)) {
                extensions.push_back(extension_type);

                if (extension_type == 0x000a || extension_type == 0x002b) {
                    auto const prefix_size = extension_type == 0x000a ? 2U : 1U;
                    if (extension_len < prefix_size + 2) return 14;
                    auto const vector_size = prefix_size == 2
                        ? static_cast<std::size_t>((buffer[payload] << 8)
                                                   | buffer[payload + 1])
                        : static_cast<std::size_t>(buffer[payload]);
                    if ((vector_size & 1U) != 0
                        || vector_size != extension_len - prefix_size) return 14;
                    if (extension_type == 0x002b) {
                        uint16_t selected = 0;
                        for (std::size_t cursor = 0; cursor < vector_size; cursor += 2) {
                            auto const candidate = static_cast<uint16_t>(
                                (buffer[payload + 1 + cursor] << 8)
                                | buffer[payload + 2 + cursor]);
                            if (!util::is_grease_value(candidate)) {
                                selected = std::max(selected, candidate);
                            }
                        }
                        if (selected == 0) return 14;
                        version = selected;
                    }
                } else if (extension_type == 0x000b) {
                    if (extension_len < 2 || buffer[payload] != extension_len - 1) return 14;
                } else if (extension_type == 0x000d || extension_type == 0x0032) {
                    if (extension_len < 2) return 14;
                    uint16_t hash_len = (buffer[payload] << 8) | buffer[payload + 1];
                    if (hash_len < 2 || (hash_len & 1U) != 0
                        || hash_len != extension_len - 2) {
                        return 14;
                    }
                    if (extension_type == 0x000d) {
                        for (size_t j = 0; j < hash_len; j += 2) {
                            sigalgs.push_back((buffer[payload + 2 + j] << 8) |
                                              buffer[payload + 3 + j]);
                        }
                    }
                }
            }

            i += (extension_len + 4);
        }

        return 0;
    }
}
