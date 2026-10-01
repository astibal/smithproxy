#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <curl/curl.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

struct Log {
    std::string section;
    std::string description;
    std::string key;
};

using Bytes = std::vector<unsigned char>;
constexpr std::size_t max_download_size = 10 * 1024 * 1024;

struct DownloadBuffer {
    Bytes bytes;
    bool too_large = false;
};

struct UpdateOptions {
    std::string url;
    std::string signature_url;
    fs::path signer_key;
    fs::path cache_dir;
    fs::path output;
    int max_age_days = 70;
    int retries = 3;
    bool include_tiled = true;
};

struct CurlGlobal {
    CurlGlobal()
    {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            throw std::runtime_error("curl_global_init failed");
        }
    }
    ~CurlGlobal() { curl_global_cleanup(); }
};

std::string openssl_errors()
{
    std::ostringstream out;
    bool first = true;
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error()) {
        if (!first) out << "; ";
        first = false;
        char text[256]{};
        ERR_error_string_n(code, text, sizeof(text));
        out << text;
    }
    return out.str();
}

Bytes read_file(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open " + path.string());
    return Bytes(std::istreambuf_iterator<char>(input), {});
}

void write_atomic(const fs::path& path, const Bytes& data)
{
    if (!path.parent_path().empty()) fs::create_directories(path.parent_path());
    fs::path temporary = path;
    temporary += ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create " + temporary.string());
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        output.close();
        if (!output) throw std::runtime_error("cannot write " + temporary.string());
    }
    try {
        fs::rename(temporary, path);
    } catch (...) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw;
    }
}

std::size_t curl_write(char* data, std::size_t size, std::size_t count, void* context)
{
    const std::size_t bytes = size * count;
    auto* output = static_cast<DownloadBuffer*>(context);
    if (bytes > max_download_size - output->bytes.size()) {
        output->too_large = true;
        return 0;
    }
    output->bytes.insert(output->bytes.end(), data, data + bytes);
    return bytes;
}

Bytes download(const std::string& url)
{
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    DownloadBuffer result;
    char error[CURL_ERROR_SIZE]{};
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl.get(), CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "https,file");
    curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, "smithproxy-sx_ctlog/1");
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error);
    const CURLcode status = curl_easy_perform(curl.get());
    if (status != CURLE_OK) {
        if (result.too_large) throw std::runtime_error("download " + url + " exceeds 10 MiB");
        throw std::runtime_error("download " + url + " failed: " +
                                 (error[0] ? std::string(error) : curl_easy_strerror(status)));
    }
    long http_status = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_status);
    if (url.rfind("http", 0) == 0 && http_status != 200) {
        throw std::runtime_error("download " + url + " returned HTTP " + std::to_string(http_status));
    }
    if (result.bytes.empty()) throw std::runtime_error("download " + url + " returned an empty file");
    return std::move(result.bytes);
}

void verify_signature(const Bytes& document, const Bytes& signature, const fs::path& key_path)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free);
    if (!bio) throw std::runtime_error("cannot open signer key " + key_path.string());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!key) throw std::runtime_error("invalid signer public key: " + openssl_errors());
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1 ||
        EVP_DigestVerifyUpdate(context.get(), document.data(), document.size()) != 1 ||
        EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size()) != 1) {
        throw std::runtime_error("CT log-list signature verification failed");
    }
}

std::time_t parse_timestamp(const std::string& value)
{
    std::tm parsed{};
    std::istringstream input(value);
    input >> std::get_time(&parsed, "%Y-%m-%dT%H:%M:%SZ");
    if (value.size() != 20 || input.fail()) throw std::runtime_error("invalid log_list_timestamp: " + value);
    const std::time_t result = timegm(&parsed);
    if (result == static_cast<std::time_t>(-1)) throw std::runtime_error("invalid log_list_timestamp: " + value);
    return result;
}

void check_freshness(const json& root, int max_age_days)
{
    if (!root.contains("log_list_timestamp") || !root.at("log_list_timestamp").is_string()) {
        throw std::runtime_error("signed list has no log_list_timestamp");
    }
    const auto timestamp = parse_timestamp(root.at("log_list_timestamp").get<std::string>());
    const auto now = std::time(nullptr);
    constexpr std::time_t future_tolerance = 24 * 60 * 60;
    if (timestamp > now + future_tolerance) throw std::runtime_error("log list timestamp is in the future");
    if (max_age_days >= 0 && now - timestamp > static_cast<std::time_t>(max_age_days) * 24 * 60 * 60) {
        throw std::runtime_error("log list is older than " + std::to_string(max_age_days) + " days");
    }
}

std::vector<unsigned char> decode_base64(const std::string& encoded)
{
    if (encoded.empty() || encoded.size() % 4 != 0) {
        throw std::runtime_error("invalid base64 length");
    }
    std::vector<unsigned char> decoded(encoded.size() / 4 * 3);
    const int size = EVP_DecodeBlock(decoded.data(),
                                     reinterpret_cast<const unsigned char*>(encoded.data()),
                                     static_cast<int>(encoded.size()));
    if (size < 0) throw std::runtime_error("invalid base64 data");
    std::size_t padding = 0;
    if (!encoded.empty() && encoded.back() == '=') ++padding;
    if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=') ++padding;
    decoded.resize(static_cast<std::size_t>(size) - padding);
    return decoded;
}

std::string hex_prefix(const unsigned char* bytes, std::size_t size, std::size_t count)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < std::min(size, count); ++i) {
        out << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return out.str();
}

std::string quote_conf(std::string value)
{
    std::string out = "\"";
    for (char ch : value) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        default:
            if (std::iscntrl(static_cast<unsigned char>(ch))) out += '?';
            else out += ch;
        }
    }
    out += '"';
    return out;
}

Log parse_log(const json& item, std::set<std::string>& ids)
{
    const std::string description = item.at("description").get<std::string>();
    const std::string key_b64 = item.at("key").get<std::string>();
    const std::string id_b64 = item.at("log_id").get<std::string>();
    const auto key = decode_base64(key_b64);
    const auto expected_id = decode_base64(id_b64);

    if (expected_id.size() != SHA256_DIGEST_LENGTH) {
        throw std::runtime_error(description + ": log_id is not a SHA-256 digest");
    }

    const unsigned char* cursor = key.data();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> public_key(
        d2i_PUBKEY(nullptr, &cursor, static_cast<long>(key.size())), EVP_PKEY_free);
    if (!public_key || cursor != key.data() + key.size()) {
        throw std::runtime_error(description + ": key is not a valid DER SubjectPublicKeyInfo");
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> actual_id{};
    SHA256(key.data(), key.size(), actual_id.data());
    if (!std::equal(actual_id.begin(), actual_id.end(), expected_id.begin())) {
        throw std::runtime_error(description + ": log_id does not match SHA-256(key)");
    }

    const std::string full_id = hex_prefix(actual_id.data(), actual_id.size(), actual_id.size());
    if (!ids.insert(full_id).second) {
        throw std::runtime_error(description + ": duplicate log_id");
    }

    return {"log_" + hex_prefix(actual_id.data(), actual_id.size(), 12), description, key_b64};
}

std::vector<Log> parse_logs(const json& root, bool include_tiled)
{
    if (!root.contains("operators") || !root.at("operators").is_array()) {
        throw std::runtime_error("root.operators must be an array");
    }

    std::vector<Log> result;
    std::set<std::string> ids;
    for (const auto& op : root.at("operators")) {
        for (const char* member : {"logs", "tiled_logs"}) {
            if (std::string(member) == "tiled_logs" && !include_tiled) continue;
            if (!op.contains(member)) continue;
            if (!op.at(member).is_array()) {
                throw std::runtime_error(std::string("operator.") + member + " must be an array");
            }
            for (const auto& item : op.at(member)) result.push_back(parse_log(item, ids));
        }
    }
    if (result.empty()) throw std::runtime_error("input contains no CT logs");
    return result;
}

std::string render(const std::vector<Log>& logs, const json& root)
{
    std::ostringstream out;
    out << "# Generated by sx_ctlog; do not edit.\n";
    if (root.contains("version") && root.at("version").is_string())
        out << "# Source version: " << root.at("version").get<std::string>() << "\n";
    if (root.contains("log_list_timestamp") && root.at("log_list_timestamp").is_string())
        out << "# Source timestamp: " << root.at("log_list_timestamp").get<std::string>() << "\n";
    out << "enabled_logs = ";
    for (std::size_t i = 0; i < logs.size(); ++i) {
        if (i) out << ',';
        out << logs[i].section;
    }
    out << "\n\n";
    for (const auto& log : logs) {
        out << '[' << log.section << "]\n"
            << "description = " << quote_conf(log.description) << "\n"
            << "key = " << log.key << "\n\n";
    }
    return out.str();
}

void validate_with_openssl(const fs::path& path)
{
    std::unique_ptr<CTLOG_STORE, decltype(&CTLOG_STORE_free)> store(CTLOG_STORE_new(), CTLOG_STORE_free);
    if (!store) throw std::runtime_error("CTLOG_STORE_new failed: " + openssl_errors());
    if (CTLOG_STORE_load_file(store.get(), path.c_str()) != 1) {
        throw std::runtime_error("OpenSSL rejected generated file: " + openssl_errors());
    }
}

std::size_t install_conf(const json& root, bool include_tiled, const fs::path& output_path)
{
    const auto logs = parse_logs(root, include_tiled);
    const std::string rendered = render(logs, root);
    fs::path temporary = output_path;
    temporary += ".tmp";
    if (!output_path.parent_path().empty()) fs::create_directories(output_path.parent_path());
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create output: " + temporary.string());
        output << rendered;
        output.close();
        if (!output) throw std::runtime_error("cannot write output: " + temporary.string());
    }
    try {
        validate_with_openssl(temporary);
        fs::rename(temporary, output_path);
    } catch (...) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw;
    }
    return logs.size();
}

json parse_document(const Bytes& document)
{
    return json::parse(document.begin(), document.end());
}

std::pair<Bytes, Bytes> fetch_verified(const UpdateOptions& options)
{
    std::string last_error;
    for (int attempt = 1; attempt <= options.retries; ++attempt) {
        try {
            Bytes document = download(options.url);
            Bytes signature = download(options.signature_url);
            verify_signature(document, signature, options.signer_key);
            const json root = parse_document(document);
            check_freshness(root, options.max_age_days);
            parse_logs(root, options.include_tiled);
            return {std::move(document), std::move(signature)};
        } catch (const std::exception& error) {
            last_error = error.what();
            std::cerr << "sx_ctlog: remote attempt " << attempt << '/' << options.retries
                      << " failed: " << last_error << '\n';
        }
    }
    throw std::runtime_error(last_error);
}

std::pair<Bytes, Bytes> load_verified_cache(const UpdateOptions& options)
{
    const Bytes document = read_file(options.cache_dir / "log_list.json");
    const Bytes signature = read_file(options.cache_dir / "log_list.sig");
    verify_signature(document, signature, options.signer_key);
    const json root = parse_document(document);
    check_freshness(root, options.max_age_days);
    parse_logs(root, options.include_tiled);
    return {document, signature};
}

bool accepted_apple_state(const json& item)
{
    if (!item.contains("state") || !item.at("state").is_object()) return false;
    const auto& state = item.at("state");
    return state.contains("qualified") || state.contains("usable") ||
           state.contains("readonly") || state.contains("retired");
}

json prepare_apple(const json& apple, const std::string& timestamp)
{
    if (!apple.contains("operators") || !apple.at("operators").is_array()) {
        throw std::runtime_error("Apple list has no operators array");
    }
    json result = {
        {"version", "apple-" + std::to_string(apple.value("assetVersion", 0)) + "-" +
                        std::to_string(apple.value("assetVersionV2", 0))},
        {"log_list_timestamp", timestamp},
        {"operators", json::array()}
    };
    for (const auto& source_operator : apple.at("operators")) {
        json output_operator;
        output_operator["name"] = source_operator.value("name", "unknown");
        if (source_operator.contains("email")) output_operator["email"] = source_operator.at("email");
        output_operator["logs"] = json::array();
        output_operator["tiled_logs"] = json::array();
        for (const char* member : {"logs", "tiled_logs"}) {
            if (!source_operator.contains(member) || !source_operator.at(member).is_array()) continue;
            for (const auto& item : source_operator.at(member)) {
                if (accepted_apple_state(item)) output_operator[member].push_back(item);
            }
        }
        if (!output_operator["logs"].empty() || !output_operator["tiled_logs"].empty()) {
            result["operators"].push_back(std::move(output_operator));
        }
    }
    parse_timestamp(timestamp);
    parse_logs(result, true);
    return result;
}

std::string require_value(int& index, int argc, char** argv, const std::string& option)
{
    if (++index >= argc) throw std::runtime_error(option + " requires a value");
    return argv[index];
}

UpdateOptions parse_update_options(int argc, char** argv)
{
    UpdateOptions options;
    for (int i = 2; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--url") options.url = require_value(i, argc, argv, option);
        else if (option == "--signature-url") options.signature_url = require_value(i, argc, argv, option);
        else if (option == "--signer-key") options.signer_key = require_value(i, argc, argv, option);
        else if (option == "--cache-dir") options.cache_dir = require_value(i, argc, argv, option);
        else if (option == "--output") options.output = require_value(i, argc, argv, option);
        else if (option == "--max-age-days") options.max_age_days = std::stoi(require_value(i, argc, argv, option));
        else if (option == "--retries") options.retries = std::stoi(require_value(i, argc, argv, option));
        else if (option == "--exclude-tiled") options.include_tiled = false;
        else throw std::runtime_error("unknown option: " + option);
    }
    if (options.url.empty() || options.signature_url.empty() || options.signer_key.empty() ||
        options.cache_dir.empty() || options.output.empty()) {
        throw std::runtime_error("update requires --url, --signature-url, --signer-key, --cache-dir and --output");
    }
    if (options.retries < 1 || options.retries > 20) throw std::runtime_error("--retries must be 1..20");
    if (options.max_age_days < 0) throw std::runtime_error("--max-age-days must not be negative");
    return options;
}

void usage(const char* argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " convert [--exclude-tiled] INPUT.json OUTPUT.cnf\n"
        << "  " << argv0 << " prepare-apple INPUT.json OUTPUT.json --timestamp YYYY-MM-DDTHH:MM:SSZ\n"
        << "  " << argv0 << " update --url URL --signature-url URL --signer-key KEY.pem\n"
        << "      --cache-dir DIR --output OUTPUT.cnf [--max-age-days 70] [--retries 3]\n";
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const CurlGlobal curl_global;
        if (argc < 2) {
            usage(argv[0]);
            return 2;
        }
        const std::string command = argv[1];
        if (command == "convert") {
            bool include_tiled = true;
            int arg = 2;
            if (arg < argc && std::string(argv[arg]) == "--exclude-tiled") {
                include_tiled = false;
                ++arg;
            }
            if (argc - arg != 2) {
                usage(argv[0]);
                return 2;
            }
            const fs::path input_path = argv[arg];
            const fs::path output_path = argv[arg + 1];
            const Bytes document = read_file(input_path);
            const auto count = install_conf(parse_document(document), include_tiled, output_path);
            std::cout << "Wrote " << count << " CT log keys to " << output_path << "\n";
        } else if (command == "prepare-apple") {
            if (argc != 6 || std::string(argv[4]) != "--timestamp") {
                usage(argv[0]);
                return 2;
            }
            const json normalized = prepare_apple(parse_document(read_file(argv[2])), argv[5]);
            const std::string serialized = normalized.dump(2) + "\n";
            write_atomic(argv[3], Bytes(serialized.begin(), serialized.end()));
            std::cout << "Prepared " << parse_logs(normalized, true).size()
                      << " accepted Apple CT log keys in " << argv[3] << "\n";
        } else if (command == "update") {
            const UpdateOptions options = parse_update_options(argc, argv);
            std::pair<Bytes, Bytes> source;
            bool cache_used = false;
            try {
                source = fetch_verified(options);
            } catch (const std::exception& remote_error) {
                std::cerr << "sx_ctlog: remote update unavailable (" << remote_error.what()
                          << "); trying verified cache\n";
                source = load_verified_cache(options);
                cache_used = true;
            }
            const json root = parse_document(source.first);
            const auto count = install_conf(root, options.include_tiled, options.output);
            if (!cache_used) {
                write_atomic(options.cache_dir / "log_list.json", source.first);
                write_atomic(options.cache_dir / "log_list.sig", source.second);
            }
            std::cout << "Wrote " << count << " CT log keys to " << options.output
                      << (cache_used ? " (verified cache)\n" : " (verified download)\n");
        } else {
            usage(argv[0]);
            return 2;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "sx_ctlog: " << error.what() << '\n';
        return 1;
    }
}
