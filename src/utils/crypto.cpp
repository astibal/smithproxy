#include "crypto.hpp"
#include <ossl_util.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <charconv>
#include <limits>
#include <vector>

namespace {

constexpr std::string_view password_prefix = "$pbkdf2-sha256$";
constexpr std::size_t password_salt_bytes = 16;
constexpr std::size_t password_digest_bytes = 32;
constexpr std::size_t maximum_password_bytes = 1024;

std::optional<unsigned char> decode_nibble(char character) {
    if(character >= '0' && character <= '9')
        return static_cast<unsigned char>(character - '0');
    if(character >= 'a' && character <= 'f')
        return static_cast<unsigned char>(character - 'a' + 10);
    return std::nullopt;
}

std::optional<std::vector<unsigned char>> decode_hex(std::string_view value) {
    if(value.empty() || value.size() % 2U != 0U) return std::nullopt;

    std::vector<unsigned char> result(value.size() / 2U);
    for(std::size_t index = 0; index < result.size(); ++index) {
        const auto high = decode_nibble(value[index * 2U]);
        const auto low = decode_nibble(value[index * 2U + 1U]);
        if(!high || !low) return std::nullopt;
        result[index] = static_cast<unsigned char>((*high << 4U) | *low);
    }
    return result;
}

std::optional<std::array<unsigned char, password_digest_bytes>> derive_password(
    std::string_view password,
    const std::vector<unsigned char>& salt,
    unsigned iterations) {
    const bool valid_password = !password.empty() && password.size() <= maximum_password_bytes;
    const bool valid_salt = salt.size() == password_salt_bytes;
    const bool valid_iterations = iterations > 0U &&
        iterations <= static_cast<unsigned>(std::numeric_limits<int>::max());
    if(!valid_password || !valid_salt || !valid_iterations) return std::nullopt;

    std::array<unsigned char, password_digest_bytes> digest{};
    const int derived = PKCS5_PBKDF2_HMAC(
        password.data(), static_cast<int>(password.size()),
        salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations),
        EVP_sha256(), static_cast<int>(digest.size()), digest.data());
    if(derived != 1) return std::nullopt;
    return digest;
}

struct ParsedPasswordVerifier {
    unsigned iterations = 0;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> digest;
};

std::optional<ParsedPasswordVerifier> parse_password_verifier(std::string_view verifier) {
    if(verifier.size() < password_prefix.size() ||
       verifier.substr(0, password_prefix.size()) != password_prefix) return std::nullopt;
    verifier.remove_prefix(password_prefix.size());

    const auto iterations_end = verifier.find('$');
    if(iterations_end == std::string_view::npos) return std::nullopt;
    const auto salt_end = verifier.find('$', iterations_end + 1U);
    if(salt_end == std::string_view::npos ||
       verifier.find('$', salt_end + 1U) != std::string_view::npos) return std::nullopt;

    unsigned iterations = 0;
    const auto iteration_text = verifier.substr(0, iterations_end);
    const auto parsed = std::from_chars(
        iteration_text.data(), iteration_text.data() + iteration_text.size(), iterations);
    const bool valid_iterations = parsed.ec == std::errc{} &&
        parsed.ptr == iteration_text.data() + iteration_text.size() &&
        iterations == sx::crypto::password_pbkdf2_iterations;
    if(!valid_iterations) return std::nullopt;

    auto salt = decode_hex(verifier.substr(
        iterations_end + 1U, salt_end - iterations_end - 1U));
    auto digest = decode_hex(verifier.substr(salt_end + 1U));
    if(!salt || salt->size() != password_salt_bytes ||
       !digest || digest->size() != password_digest_bytes) return std::nullopt;

    return ParsedPasswordVerifier{iterations, std::move(*salt), std::move(*digest)};
}

} // namespace

namespace sx::crypto {

std::string hex(unsigned char const* data, std::size_t size) {
    return socle::ossl::hex_encode(data, size);
}

std::optional<std::string> sha256(std::string_view input) {
    return socle::ossl::sha256(input);
}

std::optional<std::string> random_hex(std::size_t bytes) {
    return socle::ossl::random_hex(bytes);
}

std::optional<std::string> password_verifier(std::string_view password) {
    const auto salt_text = random_hex(password_salt_bytes);
    if(!salt_text) return std::nullopt;
    const auto salt = decode_hex(*salt_text);
    if(!salt) return std::nullopt;

    auto digest = derive_password(password, *salt, password_pbkdf2_iterations);
    if(!digest) return std::nullopt;

    auto result = std::string(password_prefix) +
        std::to_string(password_pbkdf2_iterations) + "$" + *salt_text + "$" +
        hex(digest->data(), digest->size());
    OPENSSL_cleanse(digest->data(), digest->size());
    return result;
}

bool password_matches(std::string_view password, std::string_view verifier) {
    const auto parsed = parse_password_verifier(verifier);
    if(!parsed) return false;

    auto candidate = derive_password(password, parsed->salt, parsed->iterations);
    if(!candidate) return false;
    const bool matches = CRYPTO_memcmp(
        candidate->data(), parsed->digest.data(), candidate->size()) == 0;
    OPENSSL_cleanse(candidate->data(), candidate->size());
    return matches;
}

bool password_verifier_supported(std::string_view verifier) {
    return parse_password_verifier(verifier).has_value();
}

} // namespace sx::crypto
