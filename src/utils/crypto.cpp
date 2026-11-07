#include "crypto.hpp"

#include <array>
#include <climits>
#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace sx::crypto {

std::string hex(unsigned char const* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for(std::size_t index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(data[index]);
    }

    return output.str();
}

std::optional<std::string> sha256(std::string_view input) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digest_size = 0;

    using DigestCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestCtx context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!context) {
        return std::nullopt;
    }

    bool const initialized = EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1;
    bool const updated = initialized &&
        EVP_DigestUpdate(context.get(), input.data(), input.size()) == 1;
    bool const finalized = updated &&
        EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) == 1;

    if(!finalized) {
        return std::nullopt;
    }

    return hex(digest.data(), digest_size);
}

std::optional<std::string> random_hex(std::size_t bytes) {
    if(bytes == 0 || bytes > static_cast<std::size_t>(INT_MAX)) {
        return std::nullopt;
    }

    std::vector<unsigned char> random(bytes);
    if(RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        return std::nullopt;
    }

    return hex(random.data(), random.size());
}

}  // namespace sx::crypto
