#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace sx::crypto {

// Encode binary data as lowercase hexadecimal text.
std::string hex(unsigned char const* data, std::size_t size);

// Return a lowercase SHA-256 digest. Failure means OpenSSL could not complete
// the digest operation; an empty input is valid and still produces a digest.
std::optional<std::string> sha256(std::string_view input);

// Generate the requested number of random bytes and return them as lowercase
// hexadecimal text.
std::optional<std::string> random_hex(std::size_t bytes);

}  // namespace sx::crypto
