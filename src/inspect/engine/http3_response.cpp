#include <inspect/engine/http3_response.hpp>
#include <inspect/engine/http3_wire.hpp>

#include <array>
#include <string>
#include <vector>
#include <lsqpack.h>
#include <lsxpack_header.h>

namespace sx::engine::http::v3 {
std::optional<buffer> make_response(std::string_view body, unsigned status, bool head_only) {
    if (status < 200 || status > 599) return std::nullopt;

    const bool body_forbidden = status == 204 || status == 205 || status == 304;
    // Local replies must not depend on a dynamic QPACK table or encoder stream.
    lsqpack_enc encoder {};
    std::array<unsigned char, LSQPACK_LONGEST_SDTC> instruction {};
    std::size_t instruction_size = instruction.size();

    if (lsqpack_enc_init(&encoder, nullptr, 0, 0, 0, static_cast<lsqpack_enc_opts>(0),
                        instruction.data(), &instruction_size) != 0) return std::nullopt;

    struct cleanup {
        lsqpack_enc* encoder;

        ~cleanup() { lsqpack_enc_cleanup(encoder); }
    } guard {&encoder};

    if (lsqpack_enc_start_header(&encoder, 0, 0) != 0) return std::nullopt;

    std::vector<std::pair<std::string, std::string>> fields {
        {":status", std::to_string(status)},
        {"content-type", "text/html; charset=utf-8"},
        {"cache-control", "no-store"}
    };

    if (!body_forbidden) fields.emplace_back("content-length", std::to_string(body.size()));

    buffer encoded;

    for (auto const& [name, value] : fields) {
        auto storage = name + value;
        lsxpack_header header {};

        lsxpack_header_set_offset2(&header, storage.data(), 0, name.size(), name.size(), value.size());

        std::array<unsigned char, 16> instructions {};
        std::array<unsigned char, 256> bytes {};
        auto instructions_size = instructions.size();
        auto bytes_size = bytes.size();

        if (lsqpack_enc_encode(&encoder, instructions.data(), &instructions_size,
                              bytes.data(), &bytes_size, &header,
                              static_cast<lsqpack_enc_flags>(LQEF_NO_INDEX | LQEF_NO_DYN)) != LQES_OK
            || instructions_size != 0) return std::nullopt;

        encoded.append(bytes.data(), bytes_size);
    }

    std::array<unsigned char, 32> prefix {};
    lsqpack_enc_header_flags flags {};
    auto const prefix_size = lsqpack_enc_end_header(&encoder, prefix.data(), prefix.size(), &flags);

    if (prefix_size <= 0) return std::nullopt;

    // Frame payload length includes the QPACK prefix and the encoded fields.
    buffer result;

    append_varint(result, 1); // HEADERS
    if (!append_varint(result, static_cast<std::size_t>(prefix_size) + encoded.size())) {
        return std::nullopt;
    }

    result.append(prefix.data(), static_cast<std::size_t>(prefix_size));
    result.append(encoded);

    if (!head_only && !body_forbidden && !body.empty()) {
        append_varint(result, 0); // DATA; transport owns the subsequent FIN.
        if (!append_varint(result, body.size())) {
            return std::nullopt;
        }

        result.append(body.data(), body.size());
    }

    return result;
}

} // namespace sx::engine::http::v3
