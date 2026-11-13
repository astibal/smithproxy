#pragma once

#include <dependency_build_info.hpp>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <dlfcn.h>
#include <nlohmann/json.hpp>
#include <string>
#ifdef SMITHPROXY_ENABLE_NGTCP2
#include <ngtcp2/ngtcp2.h>
#endif

namespace sx::dependencies {

// A build prefix cannot prove package ownership. Report external OpenSSL and
// the actual loader paths instead of labelling custom libraries as distro ones.
inline std::string loaded_library(const char* symbol, const std::string& linkage) {
    if(linkage != "dynamic") return {};
    Dl_info info {};
    if(dladdr(dlsym(RTLD_DEFAULT, symbol), &info) != 0 && info.dli_fname) return info.dli_fname;
    return {};
}

// Both CLI and HTTP status consume this snapshot; runtime versions are queried
// from the linked implementation, not inferred from filenames or SONAMEs.
inline nlohmann::json status() {
    nlohmann::json result;
    result["openssl"] = {
        {"version", OpenSSL_version(OPENSSL_VERSION)},
        {"build_version", build::openssl_version},
        {"linkage", build::ssl_linkage},
        {"source", "external"},
        {"build_library", build::ssl_library},
        {"loaded_library", loaded_library("SSL_new", build::ssl_linkage)},
        {"crypto_linkage", build::crypto_linkage},
        {"crypto_build_library", build::crypto_library},
        {"crypto_loaded_library", loaded_library("OpenSSL_version", build::crypto_linkage)}
    };
#ifdef SMITHPROXY_ENABLE_NGTCP2
    result["ngtcp2"] = {
        {"enabled", true},
        {"version", ngtcp2_version(0)->version_str},
        {"linkage", "static"},
        {"source", "submodule"},
        {"commit", build::ngtcp2_commit},
        {"crypto_adapter", "ossl"}
    };
#else
    result["ngtcp2"] = {{"enabled", false}, {"linkage", "disabled"}};
#endif
    return result;
}

} // namespace sx::dependencies
