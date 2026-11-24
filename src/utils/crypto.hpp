#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace sx::crypto {

// OWASP's PBKDF2-HMAC-SHA256 work factor. The value is encoded into each
// verifier so a later schema can migrate it explicitly.
inline constexpr unsigned password_pbkdf2_iterations = 600000;

// Encode binary data as lowercase hexadecimal text.
std::string hex(unsigned char const* data, std::size_t size);

// Return a lowercase SHA-256 digest. Failure means OpenSSL could not complete
// the digest operation; an empty input is valid and still produces a digest.
std::optional<std::string> sha256(std::string_view input);

// Generate the requested number of random bytes and return them as lowercase
// hexadecimal text.
std::optional<std::string> random_hex(std::size_t bytes);

// Create a self-describing PBKDF2-SHA256 verifier for a management password.
// Plaintext passwords are never retained by this API.
std::optional<std::string> password_verifier(std::string_view password);

// Compare a password with a verifier in constant time. Unsupported or
// malformed verifier formats fail closed.
bool password_matches(std::string_view password, std::string_view verifier);

// Report whether text is a structurally valid verifier supported by this
// build, without attempting authentication.
bool password_verifier_supported(std::string_view verifier);

}  // namespace sx::crypto
