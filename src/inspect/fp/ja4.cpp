#include <inspect/fp/ja4.hpp>
#include <ossl_util.hpp>

namespace sx::ja4 {

    namespace {
        constexpr size_t fingerprint_hash_length = 12;
        constexpr size_t maximum_fingerprint_count = 99;

        namespace tls_extension {
            constexpr uint16_t server_name = 0;
            constexpr uint16_t supported_groups = 10;
            constexpr uint16_t point_formats = 11;
            constexpr uint16_t signature_algorithms = 13;
            constexpr uint16_t alpn = 16;
            constexpr uint16_t supported_versions = 43;
            constexpr uint16_t signature_algorithms_cert = 50;
            constexpr uint16_t key_share = 51;
        }

        // JA4 uses zeros for absent input, not SHA-256 of the empty string.
        // A hashing failure remains distinguishable from a legitimately absent field.
        std::string fingerprint_hash(std::string_view input) {
            if (input.empty()) return std::string(fingerprint_hash_length, '0');
            return util::hash_sha256(input).value_or("<error>")
                .substr(0, fingerprint_hash_length);
        }

        std::string tls_version(uint16_t version) {
            switch (version) {
                case 0x0002: return "s2";
                case 0x0300: return "s3";
                case 0x0301: return "10";
                case 0x0302: return "11";
                case 0x0303: return "12";
                case 0x0304: return "13";
                default: return "00";
            }
        }

        // Use ASCII rules regardless of process locale. Non-alphanumeric
        // endpoints use the first/last hex digit of the original ALPN bytes.
        std::string alpn_code(std::string_view value) {
            if (value.empty()) return "00";
            auto first = static_cast<unsigned char>(value.front());
            auto last = static_cast<unsigned char>(value.back());
            auto ascii_alnum = [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z');
            };
            if (ascii_alnum(first) && ascii_alnum(last))
                return std::string{static_cast<char>(first), static_cast<char>(last)};
            return std::string{util::to_hex_string_1B(first)[0],
                               util::to_hex_string_1B(last)[1]};
        }

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

            return socle::ossl::sha256(input);
        }

        std::string to_dec_2B(size_t count) {
            std::stringstream ss;
            ss << std::setw(2) << std::setfill('0') << std::min(count, maximum_fingerprint_count);
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


        // GREASE repeats the same byte: 0x0a0a, 0x1a1a, ... 0xfafa.
        // Matching low nibbles alone would also discard legitimate values.
        bool is_grease_value(uint16_t value) {
            return (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xff);
        }

        static std::optional<std::string> make_ja4(std::string_view input) {

            // Raw layout: prefix_ciphers_extensions[_signature_algorithms].
            // Only the first two separators delimit fields; the optional third
            // belongs to the extension/signature hash input.
            const auto cipher_separator = input.find('_');
            if (cipher_separator == std::string_view::npos) return std::nullopt;
            const auto extension_separator = input.find('_', cipher_separator + 1);
            if (extension_separator == std::string_view::npos) return std::nullopt;

            const auto prefix = input.substr(0, cipher_separator);
            const auto ciphers = input.substr(
                cipher_separator + 1, extension_separator - cipher_separator - 1);
            const auto extensions_and_signatures = input.substr(extension_separator + 1);
            return std::string(prefix) + "_" + fingerprint_hash(ciphers)
                + "_" + fingerprint_hash(extensions_and_signatures);
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

        // Invalidate derived strings when streaming in another header.
        clear();
        // HTTP/2 pseudo-headers supply request context, not JA4H header counts/hashes.
        if (header_pair.first.empty() || header_pair.first.front() == ':') return false;
        auto locase = util::to_lower(header_pair.first);
        if(locase == "cookie") {
            have_cookie = true;
            if(should_parse_cookies) {
                auto ck = util::split_string_view(header_pair.second, ";", false, true);
                for(auto cookie_pair: ck) {
                    cookie_pair = trim_ows(cookie_pair);
                    // Split on the first '=' only; values may contain more (e.g. base64).
                    auto equals = cookie_pair.find('=');
                    auto name = trim_ows(cookie_pair.substr(0, equals));
                    if (name.empty()) continue;
                    cookies.push_back(name);
                    cookies_values.emplace_back(cookie_pair);
                }
            }

            return true;
        }
        else if(locase == "referer") {
            have_referer = true;
            return true;
        }
        else if(locase == "accept-language") {
            // Only the first language range contributes, without '-' or quality.
            // Stop before padding: a long tag must never underflow the pad length.
            lang.clear();
            for (unsigned char c : header_pair.second) {
                if (c == ',' || c == ';' || lang.size() == 4) break;
                if (c != '-') lang += static_cast<char>(std::tolower(c));
            }
            lang.append(4 - lang.size(), '0');
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
        // JA4H sorts by cookie name. Equal names keep their original order;
        // sorting entire name=value strings would make values affect this order.
        std::stable_sort(cookies_copy.begin(), cookies_copy.end(),
            [](std::string_view a, std::string_view b) {
                return a.substr(0, a.find('=')) < b.substr(0, b.find('='));
            });

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

        result_b = fingerprint_hash(ja4h_b_raw());
        return result_b;
    }

    std::string HTTP::ja4h_c() const {
        if(! result_c.empty()) return result_c;

        result_c = fingerprint_hash(ja4h_c_raw());
        return result_c;
    }

    std::string HTTP::ja4h_d() const {
        if(! result_d.empty()) return result_d;

        result_d = fingerprint_hash(ja4h_d_raw());
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
        const auto line_end = data.find_first_of("\r\n");
        const auto request_line = data.substr(0, line_end);
        const auto version_pos = request_line.rfind(" HTTP/");
        version = "00";
        if (version_pos != std::string_view::npos) {
            const auto token = request_line.substr(version_pos + 6);
            if (token == "1.0") version = "10";
            else if (token == "1.1") version = "11";
        }
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
        alpn = "00";
        extensions.clear();
        result_r.clear();
        result.clear();

        size_t offset = 4;
        if (offset + 2 > data.size()) return 1;

        // Parse the TLS protocol version.
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
            if (ext_type == tls_extension::supported_versions) {
                if (ext_len != 2) return 11;
                auto const selected = static_cast<uint16_t>(
                    (data[payload] << 8) | data[payload + 1]);
                if (util::is_grease_value(selected)) return 11;
                version = selected;
            }
            // TLS 1.2 carries selected ALPN here. TLS 1.3 sends it in
            // EncryptedExtensions, which is outside the JA4S input.
            if (ext_type == tls_extension::alpn) {
                if (ext_len < 4) return 11;
                const size_t list_size = (data[payload] << 8) | data[payload + 1];
                const size_t name_size = data[payload + 2];
                if (list_size != static_cast<size_t>(ext_len) - 2 || name_size == 0 || name_size + 1 != list_size)
                    return 11;
                alpn = alpn_code(std::string_view(
                    reinterpret_cast<const char*>(&data[payload + 3]), name_size));
            }
            if(ext_type == tls_extension::key_share) {
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
        return tls_version(version);
    }

    std::string TLSServerHello::exn() const {
        return util::to_dec_2B(extensions.size());
    }

    std::string TLSServerHello::prefix() const {
        std::stringstream fingerprint;
        // t - tcp / q - quic

        fingerprint << proto << ver() << exn() << alpn << "_" << util::to_hex_string_2B(cipher_suite);
        return fingerprint.str();
    }

    std::string TLSServerHello::ext_string() const {
        // JA4S keeps ServerHello extension order (unlike sorted ClientHello JA4).

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

        result = prefix() + "_" + fingerprint_hash(ext_string());
        return result;
    }



    void TLSClientHello::clear() {
        version = 0;
        have_key_share = false;
        sni = false;
        alpn = "00";
        have_alpn = false;
        cipher_suites.clear();
        extensions.clear();
        sigalgs.clear();

        results.clear();
    }

    std::string TLSClientHello::ver() const {
        return tls_version(version);
    }

    std::string TLSClientHello::di() const { return ( (sni && ! ignore_sni) ? "d" : "i"); }

    std::string TLSClientHello::cs() const {
        return util::to_dec_2B(cipher_suites.size());
    }

    std::string TLSClientHello::ex() const {
        auto count = extensions.size();
        // SNI and ALPN are excluded from the extension hash, but still count
        // in standard JA4. Only our no-SNI variant omits SNI from this count.
        if (have_alpn) ++count;
        if (sni && !ignore_sni) ++count;
        return util::to_dec_2B(count);
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
        // The separator is absent when no signature algorithms were sent.
        if (!sigalgs.empty()) fingerprint << "_";

        // Preserve signature algorithm preference order; do not sort these.
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

    // Input starts with the four-byte TLS handshake header, not a TLS record header.
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
            if (!util::is_grease_value(cipher_suite)) cipher_suites.push_back(cipher_suite);
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

            if (extension_type == tls_extension::server_name) {
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
            } else if (extension_type == tls_extension::alpn) {
                // ALPN is counted even when its encoded value is "00".
                have_alpn = true;
                if (extension_len < 3) return 14;
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
                    alpn = alpn_code(fst_alpn);
                }
            } else if(extension_type == tls_extension::key_share) {
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

                if (extension_type == tls_extension::supported_groups || extension_type == tls_extension::supported_versions) {
                    auto const prefix_size = extension_type == tls_extension::supported_groups ? 2U : 1U;
                    if (extension_len < prefix_size + 2) return 14;
                    auto const vector_size = prefix_size == 2
                        ? static_cast<std::size_t>((buffer[payload] << 8)
                                                   | buffer[payload + 1])
                        : static_cast<std::size_t>(buffer[payload]);
                    if ((vector_size & 1U) != 0
                        || vector_size != extension_len - prefix_size) return 14;
                    if (extension_type == tls_extension::supported_versions) {
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
                } else if (extension_type == tls_extension::point_formats) {
                    if (extension_len < 2 || buffer[payload] != extension_len - 1) return 14;
                } else if (extension_type == tls_extension::signature_algorithms || extension_type == tls_extension::signature_algorithms_cert) {
                    if (extension_len < 2) return 14;
                    uint16_t hash_len = (buffer[payload] << 8) | buffer[payload + 1];
                    if (hash_len < 2 || (hash_len & 1U) != 0
                        || hash_len != extension_len - 2) {
                        return 14;
                    }
                    if (extension_type == tls_extension::signature_algorithms) {
                        for (size_t j = 0; j < hash_len; j += 2) {
                            auto value = static_cast<uint16_t>((buffer[payload + 2 + j] << 8) |
                                                               buffer[payload + 3 + j]);
                            if (!util::is_grease_value(value)) sigalgs.push_back(value);
                        }
                    }
                }
            }

            i += (extension_len + 4);
        }

        return 0;
    }
}
