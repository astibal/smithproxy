#include <gtest/gtest.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sslcertstore.hpp>
#include <sslcertval.hpp>
#include <sslmitmcom.hpp>
#include <log/logger.hpp>
#include <async/asyncsocket.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace {

using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using crl_ptr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;
using ocsp_response_ptr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
using x509_store_ptr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;

x509_ptr load_certificate(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, X509_free};
    X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {certificate, X509_free};
}

pkey_ptr load_private_key(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return {key, EVP_PKEY_free};
}

bool write_certificate_file(const std::filesystem::path& path,
                            const std::vector<X509*>& certificates) {
    FILE* file = fopen(path.c_str(), "w");
    if (!file)
        return false;
    bool written = true;
    for (X509* certificate : certificates) {
        if (!certificate || PEM_write_X509(file, certificate) != 1) {
            written = false;
            break;
        }
    }
    return fclose(file) == 0 && written;
}

bool write_private_key_file(const std::filesystem::path& path, EVP_PKEY* key) {
    FILE* file = fopen(path.c_str(), "w");
    if (!file)
        return false;
    const bool written = key && PEM_write_PrivateKey(file, key, nullptr, nullptr, 0,
                                                     nullptr, nullptr) == 1;
    return fclose(file) == 0 && written;
}

pkey_ptr generate_rsa_key() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0 ||
        EVP_PKEY_keygen(context.get(), &key) <= 0)
        return {nullptr, EVP_PKEY_free};
    return {key, EVP_PKEY_free};
}

bool add_certificate_extension(X509* certificate, X509* issuer, int nid,
                               const std::string& value) {
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr, &context, nid, const_cast<char*>(value.c_str()));
    if (!extension)
        return false;
    const bool added = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return added;
}

x509_ptr make_current_certificate(EVP_PKEY* key, const char* common_name,
                                  X509* issuer, EVP_PKEY* issuer_key,
                                  long serial, bool certificate_authority,
                                  const std::string& ocsp_url = {}) {
    x509_ptr certificate(X509_new(), X509_free);
    if (!certificate || !key || X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400) ||
        X509_set_pubkey(certificate.get(), key) != 1)
        return {nullptr, X509_free};

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    if (!subject ||
        X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate.get(),
                             issuer ? X509_get_subject_name(issuer) : subject) != 1)
        return {nullptr, X509_free};

    if (certificate_authority) {
        if (!add_certificate_extension(certificate.get(), certificate.get(),
                                       NID_basic_constraints, "critical,CA:TRUE") ||
            !add_certificate_extension(certificate.get(), certificate.get(),
                                       NID_key_usage, "critical,keyCertSign,cRLSign"))
            return {nullptr, X509_free};
    } else {
        if (!add_certificate_extension(certificate.get(), issuer,
                                       NID_basic_constraints, "critical,CA:FALSE") ||
            !add_certificate_extension(certificate.get(), issuer,
                                       NID_key_usage,
                                       "critical,digitalSignature,keyEncipherment") ||
            (!ocsp_url.empty() &&
             !add_certificate_extension(certificate.get(), issuer, NID_info_access,
                                        "OCSP;URI:" + ocsp_url)))
            return {nullptr, X509_free};
    }

    if (X509_sign(certificate.get(), issuer_key ? issuer_key : key, EVP_sha256()) <= 0)
        return {nullptr, X509_free};
    return certificate;
}

class OneShotOcspResponder {
public:
    explicit OneShotOcspResponder(int family = AF_INET) {
        listener_ = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener_ < 0)
            return;
        sockaddr_storage address{};
        socklen_t length = 0;
        if (family == AF_INET6) {
            auto* address6 = reinterpret_cast<sockaddr_in6*>(&address);
            address6->sin6_family = AF_INET6;
            address6->sin6_addr = in6addr_loopback;
            address6->sin6_port = 0;
            length = sizeof(*address6);
        }
        else {
            auto* address4 = reinterpret_cast<sockaddr_in*>(&address);
            address4->sin_family = AF_INET;
            address4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address4->sin_port = 0;
            length = sizeof(*address4);
        }
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
            ::listen(listener_, 1) != 0) {
            ::close(listener_);
            listener_ = -1;
            return;
        }
        length = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
            ::close(listener_);
            listener_ = -1;
            return;
        }
        port_ = family == AF_INET6
            ? ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port)
            : ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port);
    }

    ~OneShotOcspResponder() {
        if (listener_ >= 0)
            ::close(listener_);
        if (worker_.joinable())
            worker_.join();
    }

    bool valid() const { return listener_ >= 0 && port_ != 0; }
    unsigned short port() const { return port_; }

    void reply_with(OCSP_RESPONSE* response) {
        reply_with_if_request_contains(response, {});
    }

    void reply_with_if_request_contains(OCSP_RESPONSE* response,
                                        std::string required_request_text) {
        const int size = i2d_OCSP_RESPONSE(response, nullptr);
        if (size <= 0)
            return;
        std::vector<unsigned char> body(static_cast<std::size_t>(size));
        unsigned char* output = body.data();
        if (i2d_OCSP_RESPONSE(response, &output) != size)
            return;
        const std::string headers =
            "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        std::vector<unsigned char> reply(headers.begin(), headers.end());
        reply.insert(reply.end(), body.begin(), body.end());
        reply_raw(std::move(reply), std::chrono::milliseconds(0),
                  std::chrono::milliseconds(0),
                  std::numeric_limits<std::size_t>::max(),
                  std::move(required_request_text));
    }

    void reply_with_trailing_byte(OCSP_RESPONSE* response) {
        const int size = i2d_OCSP_RESPONSE(response, nullptr);
        if (size <= 0)
            return;
        std::vector<unsigned char> body(static_cast<std::size_t>(size) + 1);
        unsigned char* output = body.data();
        if (i2d_OCSP_RESPONSE(response, &output) != size)
            return;
        body.back() = 0x00;
        const std::string headers =
            "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        std::vector<unsigned char> reply(headers.begin(), headers.end());
        reply.insert(reply.end(), body.begin(), body.end());
        reply_raw(std::move(reply));
    }

    void reply_raw(std::string reply) {
        reply_raw(std::vector<unsigned char>(reply.begin(), reply.end()));
    }

    void reply_after(std::string reply, std::chrono::milliseconds delay) {
        reply_raw(std::vector<unsigned char>(reply.begin(), reply.end()), delay);
    }

    void reply_in_chunks(std::string reply, std::chrono::milliseconds delay,
                         std::size_t chunk_size) {
        reply_raw(std::vector<unsigned char>(reply.begin(), reply.end()),
                  std::chrono::milliseconds(0), delay, chunk_size);
    }

private:
    void reply_raw(std::vector<unsigned char> reply,
                   std::chrono::milliseconds delay = std::chrono::milliseconds(0),
                   std::chrono::milliseconds chunk_delay = std::chrono::milliseconds(0),
                   std::size_t chunk_size = std::numeric_limits<std::size_t>::max(),
                   std::string required_request_text = {}) {
        worker_ = std::thread([this, reply = std::move(reply), delay,
                               chunk_delay, chunk_size,
                               required_request_text = std::move(required_request_text)] {
            pollfd ready{listener_, POLLIN, 0};
            if (::poll(&ready, 1, 5000) <= 0)
                return;
            const int client = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0)
                return;

            std::string request;
            std::array<char, 2048> input{};
            while (request.find("\r\n\r\n") == std::string::npos) {
                const ssize_t count = ::recv(client, input.data(), input.size(), 0);
                if (count <= 0)
                    break;
                request.append(input.data(), static_cast<std::size_t>(count));
            }

            if (!required_request_text.empty() &&
                request.find(required_request_text) == std::string::npos) {
                ::close(client);
                return;
            }

            if (delay.count() > 0)
                std::this_thread::sleep_for(delay);

            std::size_t sent = 0;
            while (sent < reply.size()) {
                const std::size_t remaining = reply.size() - sent;
                const std::size_t send_size = chunk_size < remaining
                    ? chunk_size : remaining;
                const ssize_t count = ::send(client, reply.data() + sent,
                                             send_size, MSG_NOSIGNAL);
                if (count <= 0)
                    break;
                sent += static_cast<std::size_t>(count);
                if (sent < reply.size() && chunk_delay.count() > 0)
                    std::this_thread::sleep_for(chunk_delay);
            }
            ::close(client);
        });
    }

    int listener_ = -1;
    unsigned short port_ = 0;
    std::thread worker_;
};

class EnvironmentOverride {
public:
    EnvironmentOverride(const char* name, const std::string& value) : name_(name) {
        if (const char* current = std::getenv(name)) {
            old_value_ = current;
            had_value_ = true;
        }
        ::setenv(name_.c_str(), value.c_str(), 1);
    }
    ~EnvironmentOverride() {
        if (had_value_)
            ::setenv(name_.c_str(), old_value_.c_str(), 1);
        else
            ::unsetenv(name_.c_str());
    }

private:
    std::string name_;
    std::string old_value_;
    bool had_value_ = false;
};

crl_ptr make_crl(X509* issuer, EVP_PKEY* issuer_key, X509* revoked_certificate) {
    crl_ptr crl(X509_CRL_new(), X509_CRL_free);
    if (!crl || X509_CRL_set_version(crl.get(), 1) != 1 ||
        X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) != 1)
        return {nullptr, X509_CRL_free};

    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last_update(
        ASN1_TIME_adj(nullptr, time(nullptr), 0, -60), ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next_update(
        ASN1_TIME_adj(nullptr, time(nullptr), 1, 0), ASN1_TIME_free);
    if (!last_update || !next_update ||
        X509_CRL_set1_lastUpdate(crl.get(), last_update.get()) != 1 ||
        X509_CRL_set1_nextUpdate(crl.get(), next_update.get()) != 1)
        return {nullptr, X509_CRL_free};

    if (revoked_certificate) {
        X509_REVOKED* revoked = X509_REVOKED_new();
        ASN1_INTEGER* serial = ASN1_INTEGER_dup(X509_get0_serialNumber(revoked_certificate));
        ASN1_TIME* revoked_at = ASN1_TIME_adj(nullptr, time(nullptr), 0, -30);
        if (!revoked || !serial || !revoked_at ||
            X509_REVOKED_set_serialNumber(revoked, serial) != 1 ||
            X509_REVOKED_set_revocationDate(revoked, revoked_at) != 1 ||
            X509_CRL_add0_revoked(crl.get(), revoked) != 1) {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revoked_at);
            return {nullptr, X509_CRL_free};
        }
        ASN1_INTEGER_free(serial);
        ASN1_TIME_free(revoked_at);
        X509_CRL_sort(crl.get());
    }

    if (X509_CRL_sign(crl.get(), issuer_key, EVP_sha256()) <= 0)
        return {nullptr, X509_CRL_free};
    return crl;
}

struct ocsp_entry {
    X509* certificate;
    int status;
};

ocsp_response_ptr make_ocsp_response(X509* issuer, EVP_PKEY* issuer_key,
                                     const std::vector<ocsp_entry>& entries,
                                     int this_update_offset = -60,
                                     int next_update_offset = 3600) {
    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    if (!basic)
        return {nullptr, OCSP_RESPONSE_free};

    bool valid = true;
    for (const auto& entry : entries) {
        OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha1(), entry.certificate, issuer);
        ASN1_TIME* this_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, this_update_offset);
        ASN1_TIME* next_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, next_update_offset);
        ASN1_TIME* revoked_at = entry.status == V_OCSP_CERTSTATUS_REVOKED
                                  ? ASN1_TIME_adj(nullptr, time(nullptr), 0, -120)
                                  : nullptr;
        if (!id || !this_update || !next_update ||
            !OCSP_basic_add1_status(basic, id, entry.status,
                                    OCSP_REVOKED_STATUS_KEYCOMPROMISE,
                                    revoked_at, this_update, next_update))
            valid = false;
        OCSP_CERTID_free(id);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_TIME_free(revoked_at);
        if (!valid)
            break;
    }

    if (!valid || OCSP_basic_sign(basic, issuer, issuer_key, EVP_sha256(), nullptr, 0) != 1) {
        OCSP_BASICRESP_free(basic);
        return {nullptr, OCSP_RESPONSE_free};
    }
    OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    OCSP_BASICRESP_free(basic);
    return {response, OCSP_RESPONSE_free};
}

x509_store_ptr make_test_store(X509* trusted_certificate) {
    x509_store_ptr store(X509_STORE_new(), X509_STORE_free);
    if (!store || X509_STORE_add_cert(store.get(), trusted_certificate) != 1)
        return {nullptr, X509_STORE_free};
    // The repository fixture was intentionally short-lived in 2020. Pinning
    // verification inside that validity window tests trust, not wall-clock age.
    X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), 1583000000);
    return store;
}

int select_h2(SSL*, const unsigned char** out, unsigned char* out_length,
              const unsigned char* input, unsigned int input_length, void*) {
    static constexpr unsigned char supported[] = {2, 'h', '2'};
    return SSL_select_next_proto(
               const_cast<unsigned char**>(out), out_length,
               supported, sizeof(supported), input, input_length) == OPENSSL_NPN_NEGOTIATED
               ? SSL_TLSEXT_ERR_OK
               : SSL_TLSEXT_ERR_NOACK;
}

struct handshake_result {
    bool complete = false;
    std::string sni;
    std::string alpn;
    bool application_data_ok = false;
};

handshake_result memory_handshake(X509* certificate, EVP_PKEY* key, int version,
                                  bool send_sni, int alpn_mode, std::size_t payload_size) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server_ctx(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!server_ctx || !client_ctx)
        return {};

    if (SSL_CTX_use_certificate(server_ctx.get(), certificate) != 1 ||
        SSL_CTX_use_PrivateKey(server_ctx.get(), key) != 1 ||
        SSL_CTX_check_private_key(server_ctx.get()) != 1)
        return {};

    SSL_CTX_set_min_proto_version(server_ctx.get(), version);
    SSL_CTX_set_max_proto_version(server_ctx.get(), version);
    SSL_CTX_set_min_proto_version(client_ctx.get(), version);
    SSL_CTX_set_max_proto_version(client_ctx.get(), version);
    SSL_CTX_set_alpn_select_cb(server_ctx.get(), select_h2, nullptr);

    std::unique_ptr<SSL, decltype(&SSL_free)> client(SSL_new(client_ctx.get()), SSL_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> server(SSL_new(server_ctx.get()), SSL_free);
    if (!client || !server)
        return {};

    BIO* client_bio = nullptr;
    BIO* server_bio = nullptr;
    if (BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1)
        return {};
    SSL_set_bio(client.get(), client_bio, client_bio);
    SSL_set_bio(server.get(), server_bio, server_bio);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());

    static constexpr unsigned char h2_first[] = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    static constexpr unsigned char http1_only[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    static constexpr unsigned char http1_first[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1', 2, 'h', '2'};
    if (send_sni)
        SSL_set_tlsext_host_name(client.get(), "tls-test.smithproxy.invalid");
    if (alpn_mode == 1)
        SSL_set_alpn_protos(client.get(), h2_first, sizeof(h2_first));
    else if (alpn_mode == 2)
        SSL_set_alpn_protos(client.get(), http1_only, sizeof(http1_only));
    else if (alpn_mode == 3)
        SSL_set_alpn_protos(client.get(), http1_first, sizeof(http1_first));

    bool client_done = false;
    bool server_done = false;
    for (int round = 0; round < 1000 && !(client_done && server_done); ++round) {
        if (!client_done) {
            const int result = SSL_do_handshake(client.get());
            client_done = result == 1;
            if (!client_done) {
                const int error = SSL_get_error(client.get(), result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {};
            }
        }
        if (!server_done) {
            const int result = SSL_do_handshake(server.get());
            server_done = result == 1;
            if (!server_done) {
                const int error = SSL_get_error(server.get(), result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {};
            }
        }
    }

    const char* requested_sni = SSL_get_servername(server.get(), TLSEXT_NAMETYPE_host_name);
    const unsigned char* selected_alpn = nullptr;
    unsigned int selected_alpn_length = 0;
    SSL_get0_alpn_selected(client.get(), &selected_alpn, &selected_alpn_length);

    bool application_data_ok = false;
    if (client_done && server_done) {
        const std::string payload(payload_size, 'C');
        if (payload.empty()) {
            application_data_ok = true;
        } else {
            const int written = SSL_write(client.get(), payload.data(), payload.size());
            std::string received(payload.size(), '\0');
            const int read = SSL_read(server.get(), received.data(), received.size());
            application_data_ok = written == static_cast<int>(payload.size()) &&
                                  read == written && received == payload;
        }
    }
    return {
        client_done && server_done,
        requested_sni ? requested_sni : "",
        std::string(reinterpret_cast<const char*>(selected_alpn), selected_alpn_length),
        application_data_ok};
}

class TLSIntegration : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Log::init();
        fixture_path_ = std::filesystem::temp_directory_path() /
                        ("smithproxy-tls-testbed-" + std::to_string(getpid()));
        std::filesystem::remove_all(fixture_path_);
        std::filesystem::create_directories(fixture_path_);
        std::filesystem::copy(
            std::filesystem::path(SMITHPROXY_SOURCE_DIR) / "etc/certs/default",
            fixture_path_, std::filesystem::copy_options::recursive);

        auto& factory = SSLFactory::factory();
        factory.certs_path() = fixture_path_.string() + "/";
        factory.ca_file() = (fixture_path_ / "ca-cert.pem").string();
        factory.ca_path().clear();
        factory.init();
    }

    static void TearDownTestSuite() {
        std::filesystem::remove_all(fixture_path_);
    }

    static x509_ptr upstream_certificate() {
        return load_certificate(fixture_path_ / "srv-cert.pem");
    }

    static std::filesystem::path fixture_path_;
};

std::filesystem::path TLSIntegration::fixture_path_;

class SocketPair {
public:
    SocketPair() {
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds_.data()) != 0)
            fds_ = {-1, -1};
    }
    ~SocketPair() {
        for (auto fd : fds_) {
            if (fd >= 0) ::close(fd);
        }
    }
    bool valid() const { return fds_[0] >= 0 && fds_[1] >= 0; }
    int first() const { return fds_[0]; }
    int second() const { return fds_[1]; }
    int release_first() {
        const int fd = fds_[0];
        fds_[0] = -1;
        return fd;
    }
    void close_second() {
        if (fds_[1] >= 0) {
            ::close(fds_[1]);
            fds_[1] = -1;
        }
    }
private:
    std::array<int, 2> fds_ {-1, -1};
};

class CompletingAsyncSocket final : public AsyncSocket<int> {
public:
    CompletingAsyncSocket(baseHostCX* owner, callback_t callback)
        : AsyncSocket<int>(owner, std::move(callback)) {}

    task_state_t update() override {
        result_ = 42;
        return task_state_t::FINISHED;
    }

    int const& yield() const override { return result_; }

private:
    int result_ = -1;
};

class TimeoutAsyncSocket final : public AsyncSocket<int> {
public:
    TimeoutAsyncSocket(baseHostCX* owner, callback_t callback)
        : AsyncSocket<int>(owner, std::move(callback)) {}

    task_state_t update() override {
        update_called_ = true;
        return task_state_t::RUNNING;
    }

    int const& yield() const override { return result_; }
    bool update_called() const { return update_called_; }

protected:
    void on_timeout() override { result_ = 24; }

private:
    int result_ = -1;
    bool update_called_ = false;
};

class RevocationSSLCom final : public SSLCom {
public:
    bool set_targets(X509* certificate, X509* issuer) {
        if (!certificate || !issuer || X509_up_ref(certificate) != 1)
            return false;
        if (X509_up_ref(issuer) != 1) {
            X509_free(certificate);
            return false;
        }
        sslcom_target_cert = certificate;
        sslcom_target_issuer = issuer;
        return true;
    }
};

bool attach_ocsp_response(SSL* ssl, OCSP_RESPONSE* response) {
    if (!ssl || !response)
        return false;
    const int size = i2d_OCSP_RESPONSE(response, nullptr);
    if (size <= 0)
        return false;
    auto* encoded = static_cast<unsigned char*>(OPENSSL_malloc(
        static_cast<std::size_t>(size)));
    if (!encoded)
        return false;
    unsigned char* output = encoded;
    if (i2d_OCSP_RESPONSE(response, &output) != size) {
        OPENSSL_free(encoded);
        return false;
    }
    if (SSL_set_tlsext_status_ocsp_resp(ssl, encoded, size) != 1) {
        OPENSSL_free(encoded);
        return false;
    }
    return true;
}

struct ssl_ptr_deleter {
    void operator()(SSL* value) const { SSL_free(value); }
};

TEST_F(TLSIntegration, SSLComNonblockingHandshakeBidirectionalDataAndCloseNotify) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());
    ASSERT_EQ(SSL_set_tlsext_host_name(client.get(), "tls-state.test"), 1);

    bool client_ready = false;
    for (int round = 0; round < 1000 &&
                            !(client_ready && transport->com_status()); ++round) {
        if (!client_ready) {
            const int result = SSL_connect(client.get());
            if (result == 1) {
                client_ready = true;
            } else {
                const int error = SSL_get_error(client.get(), result);
                ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                    << "client handshake error=" << error;
            }
        }
        const int result = server.read();
        ASSERT_FALSE(server.error()) << "server handshake read=" << result;
    }
    ASSERT_TRUE(client_ready);
    ASSERT_TRUE(transport->com_status());
    EXPECT_GT(transport->counters.prof_accept_cnt, 1U);
    EXPECT_EQ(transport->counters.prof_accept_ok, 1U);

    const std::string request = "request-through-sslcom";
    ASSERT_EQ(SSL_write(client.get(), request.data(), request.size()),
              static_cast<int>(request.size()));
    for (int round = 0; round < 1000 && server.readbuf()->size() < request.size(); ++round) {
        const int result = server.read();
        ASSERT_GE(result, -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_EQ(server.readbuf()->size(), request.size());
    EXPECT_EQ(std::string(reinterpret_cast<char const*>(server.readbuf()->data()),
                          server.readbuf()->size()), request);

    const std::string response = "response-through-sslcom";
    server.writebuf()->append(response.data(), response.size());
    ASSERT_EQ(server.write(), static_cast<int>(response.size()));
    std::array<char, 64> received {};
    int received_size = -1;
    for (int round = 0; round < 1000 && received_size <= 0; ++round) {
        received_size = SSL_read(client.get(), received.data(), received.size());
        if (received_size <= 0) {
            const int error = SSL_get_error(client.get(), received_size);
            ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                << "client read error=" << error;
            server.write();
        }
    }
    ASSERT_EQ(received_size, static_cast<int>(response.size()));
    EXPECT_EQ(std::string(received.data(), received_size), response);

    const int shutdown_result = SSL_shutdown(client.get());
    ASSERT_TRUE(shutdown_result == 0 || shutdown_result == 1);
    for (int round = 0; round < 1000 && !server.read_eof(); ++round)
        server.read();
    ASSERT_TRUE(server.read_eof());
    EXPECT_FALSE(server.error());
    EXPECT_FALSE(transport->error());

    const std::string final_response = "response-after-client-close-notify";
    server.writebuf()->append(final_response.data(), final_response.size());
    ASSERT_EQ(server.write(), static_cast<int>(final_response.size()));

    std::array<char, 64> final_received {};
    int final_received_size = -1;
    for (int round = 0; round < 1000 && final_received_size <= 0; ++round) {
        final_received_size = SSL_read(
            client.get(), final_received.data(), final_received.size());
        if (final_received_size <= 0) {
            const int error = SSL_get_error(client.get(), final_received_size);
            ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                << "client final read error=" << error;
            server.write();
        }
    }
    ASSERT_EQ(final_received_size, static_cast<int>(final_response.size()));
    EXPECT_EQ(std::string(final_received.data(), final_received_size), final_response);

    // Complete the opposite close_notify direction after the client has
    // already sent its own alert. This exercises simultaneous/full shutdown
    // rather than merely dropping the TCP transport.
    transport->shutdown(server.socket());
    EXPECT_EQ(SSL_shutdown(client.get()), 1);
}

TEST_F(TLSIntegration, SSLComRejectsMalformedHandshakeWithoutRetryLoop) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());
    static constexpr std::array<unsigned char, 9> malformed {
        0x16, 0x03, 0x03, 0x00, 0x04, 0xff, 0x00, 0x00, 0x00};
    ASSERT_EQ(::send(sockets.second(), malformed.data(), malformed.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(malformed.size()));

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());

    EXPECT_TRUE(transport->error());
    EXPECT_EQ(transport->counters.prof_accept_cnt, 1U);
    EXPECT_LE(server.read(), 0);
}

TEST_F(TLSIntegration, SSLComTreatsEofWithoutCloseNotifyAsTerminal) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());

    bool client_ready = false;
    for (int round = 0; round < 1000 &&
                            !(client_ready && transport->com_status()); ++round) {
        if (!client_ready) {
            const int result = SSL_connect(client.get());
            if (result == 1) {
                client_ready = true;
            } else {
                const int error = SSL_get_error(client.get(), result);
                ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                    << "client handshake error=" << error;
            }
        }
        ASSERT_GE(server.read(), -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_TRUE(client_ready);
    ASSERT_TRUE(transport->com_status());

    const std::string final_payload = "data-before-truncated-tls-eof";
    ASSERT_EQ(SSL_write(client.get(), final_payload.data(), final_payload.size()),
              static_cast<int>(final_payload.size()));

    // Drop the transport immediately after application data, without sending
    // TLS close_notify. The data must be delivered before truncation is
    // published as the terminal state.
    sockets.close_second();
    ASSERT_EQ(server.read(), static_cast<int>(final_payload.size()));
    // OpenSSL may publish the truncation alert during the same draining call,
    // but the application payload must still win and be returned intact.
    EXPECT_TRUE(server.error());
    ASSERT_EQ(server.readbuf()->size(), final_payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<char const*>(server.readbuf()->data()),
                          server.readbuf()->size()), final_payload);

    EXPECT_EQ(server.read(), 0);
    EXPECT_TRUE(server.read_eof());
    EXPECT_TRUE(transport->error());

    // A terminal protocol error must remain terminal, not become an EAGAIN
    // loop waiting for an event which can never repair the TLS stream.
    EXPECT_EQ(server.read(), 0);
}

TEST_F(TLSIntegration, PendingTlsWriteTerminatesAfterAbruptPeerClose) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    int small_buffer = 16 * 1024;
    ASSERT_EQ(::setsockopt(sockets.first(), SOL_SOCKET, SO_SNDBUF,
                           &small_buffer, sizeof(small_buffer)), 0);

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());

    bool client_ready = false;
    for (int round = 0; round < 1000 &&
                            !(client_ready && transport->com_status()); ++round) {
        if (!client_ready) {
            const int result = SSL_connect(client.get());
            if (result == 1) {
                client_ready = true;
            } else {
                const int error = SSL_get_error(client.get(), result);
                ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                    << "client handshake error=" << error;
            }
        }
        ASSERT_GE(server.read(), -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_TRUE(client_ready);
    ASSERT_TRUE(transport->com_status());

    std::string payload(2 * 1024 * 1024, 'p');
    server.writebuf()->append(payload.data(), payload.size());
    bool blocked = false;
    for (int round = 0; round < 1000 && !server.writebuf()->empty(); ++round) {
        const int written = server.write();
        ASSERT_GE(written, 0);
        if (written == 0 && !server.writebuf()->empty()) {
            blocked = true;
            break;
        }
    }
    ASSERT_TRUE(blocked);
    ASSERT_FALSE(server.writebuf()->empty());
    EXPECT_TRUE(transport->write_event_pending());

    sockets.close_second();
    EXPECT_EQ(server.read(), 0);
    EXPECT_TRUE(transport->error());

    // Once the peer failure is known, a queued plaintext write must fail
    // terminally instead of reporting repeated zero-progress retries.
    EXPECT_LT(server.write(), 0);
}

TEST_F(TLSIntegration, ResumedTls12SessionRetainsCleanShutdownSemantics) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_2_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION), 1);
    SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_CLIENT);

    bool first_reused = false;
    bool second_reused = false;
    auto run_connection = [&](SSL_SESSION* offered_session, bool& reused)
            -> std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> {
        SocketPair sockets;
        if (!sockets.valid())
            return {nullptr, SSL_SESSION_free};

        auto* transport = new SSLCom();
        baseHostCX server(transport, sockets.release_first());
        server.opening(false);
        server.on_accept_socket(server.socket());
        if (transport->error())
            return {nullptr, SSL_SESSION_free};

        std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
        if (!client || SSL_set_fd(client.get(), sockets.second()) != 1)
            return {nullptr, SSL_SESSION_free};
        SSL_set_connect_state(client.get());
        if (offered_session && SSL_set_session(client.get(), offered_session) != 1)
            return {nullptr, SSL_SESSION_free};

        bool client_ready = false;
        for (int round = 0; round < 1000 &&
                                !(client_ready && transport->com_status()); ++round) {
            if (!client_ready) {
                const int result = SSL_connect(client.get());
                if (result == 1) {
                    client_ready = true;
                } else {
                    const int error = SSL_get_error(client.get(), result);
                    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                        return {nullptr, SSL_SESSION_free};
                }
            }
            if (server.read() < -1 || server.error())
                return {nullptr, SSL_SESSION_free};
        }
        if (!client_ready || !transport->com_status())
            return {nullptr, SSL_SESSION_free};

        reused = SSL_session_reused(client.get()) == 1;
        std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(
            SSL_get1_session(client.get()), SSL_SESSION_free);

        const int first_shutdown = SSL_shutdown(client.get());
        if (first_shutdown != 0 && first_shutdown != 1)
            return {nullptr, SSL_SESSION_free};
        for (int round = 0; round < 1000 && !server.read_eof(); ++round)
            server.read();
        if (!server.read_eof() || server.error() || transport->error())
            return {nullptr, SSL_SESSION_free};
        transport->shutdown(server.socket());
        if (SSL_shutdown(client.get()) != 1)
            return {nullptr, SSL_SESSION_free};
        return session;
    };

    auto session = run_connection(nullptr, first_reused);
    ASSERT_NE(session, nullptr);
    EXPECT_FALSE(first_reused);
    ASSERT_EQ(SSL_SESSION_is_resumable(session.get()), 1);

    auto resumed_session = run_connection(session.get(), second_reused);
    ASSERT_NE(resumed_session, nullptr);
    EXPECT_TRUE(second_reused);
}

TEST_F(TLSIntegration, TLS13KeyUpdatePreservesTransferAndCleanShutdown) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());

    bool client_ready = false;
    for (int round = 0; round < 1000 &&
                            !(client_ready && transport->com_status()); ++round) {
        if (!client_ready) {
            const int result = SSL_connect(client.get());
            if (result == 1) {
                client_ready = true;
            } else {
                const int error = SSL_get_error(client.get(), result);
                ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                    << "client handshake error=" << error;
            }
        }
        ASSERT_GE(server.read(), -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_TRUE(client_ready);
    ASSERT_TRUE(transport->com_status());
    ASSERT_EQ(SSL_version(client.get()), TLS1_3_VERSION);

    ASSERT_EQ(SSL_key_update(client.get(), SSL_KEY_UPDATE_REQUESTED), 1);
    const int update_result = SSL_do_handshake(client.get());
    ASSERT_TRUE(update_result == 1 ||
                SSL_get_error(client.get(), update_result) == SSL_ERROR_WANT_READ ||
                SSL_get_error(client.get(), update_result) == SSL_ERROR_WANT_WRITE);

    const std::string request = "request-after-tls13-key-update";
    ASSERT_EQ(SSL_write(client.get(), request.data(), request.size()),
              static_cast<int>(request.size()));
    for (int round = 0; round < 1000 && server.readbuf()->size() < request.size(); ++round) {
        ASSERT_GE(server.read(), -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_EQ(server.readbuf()->size(), request.size());
    EXPECT_EQ(std::string(reinterpret_cast<char const*>(server.readbuf()->data()),
                          server.readbuf()->size()), request);

    const std::string response = "response-after-tls13-key-update";
    server.writebuf()->append(response.data(), response.size());
    ASSERT_EQ(server.write(), static_cast<int>(response.size()));
    std::array<char, 64> received {};
    int received_size = -1;
    for (int round = 0; round < 1000 && received_size <= 0; ++round) {
        received_size = SSL_read(client.get(), received.data(), received.size());
        if (received_size <= 0) {
            const int error = SSL_get_error(client.get(), received_size);
            ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                << "client post-update read error=" << error;
            server.write();
        }
    }
    ASSERT_EQ(received_size, static_cast<int>(response.size()));
    EXPECT_EQ(std::string(received.data(), received_size), response);

    const int first_shutdown = SSL_shutdown(client.get());
    ASSERT_TRUE(first_shutdown == 0 || first_shutdown == 1);
    for (int round = 0; round < 1000 && !server.read_eof(); ++round)
        server.read();
    ASSERT_TRUE(server.read_eof());
    EXPECT_FALSE(server.error());
    transport->shutdown(server.socket());
    EXPECT_EQ(SSL_shutdown(client.get()), 1);
}

TEST_F(TLSIntegration, TLS13NewSessionTicketResumesAndShutsDownCleanly) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(client_ctx.get(), [](SSL* ssl, SSL_SESSION* session) {
        auto** captured = static_cast<SSL_SESSION**>(SSL_get_app_data(ssl));
        if (captured && !*captured && SSL_SESSION_up_ref(session) == 1)
            *captured = session;
        return 0;
    });

    auto run_connection = [&](SSL_SESSION* offered_session, bool& reused)
            -> std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> {
        SocketPair sockets;
        if (!sockets.valid())
            return {nullptr, SSL_SESSION_free};

        auto* transport = new SSLCom();
        baseHostCX server(transport, sockets.release_first());
        server.opening(false);
        server.on_accept_socket(server.socket());
        if (transport->error())
            return {nullptr, SSL_SESSION_free};

        SSL_SESSION* captured = nullptr;
        std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
        if (!client || SSL_set_fd(client.get(), sockets.second()) != 1)
            return {nullptr, SSL_SESSION_free};
        SSL_set_app_data(client.get(), &captured);
        SSL_set_connect_state(client.get());
        if (offered_session && SSL_set_session(client.get(), offered_session) != 1)
            return {nullptr, SSL_SESSION_free};

        bool client_ready = false;
        for (int round = 0; round < 1000 &&
                                !(client_ready && transport->com_status()); ++round) {
            if (!client_ready) {
                const int result = SSL_connect(client.get());
                if (result == 1) {
                    client_ready = true;
                } else {
                    const int error = SSL_get_error(client.get(), result);
                    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                        return {nullptr, SSL_SESSION_free};
                }
            }
            if (server.read() < -1 || server.error())
                return {nullptr, SSL_SESSION_free};
        }
        if (!client_ready || !transport->com_status())
            return {nullptr, SSL_SESSION_free};
        reused = SSL_session_reused(client.get()) == 1;

        // TLS 1.3 tickets arrive after the main handshake. Process records
        // until the client new-session callback receives one.
        std::array<char, 1> scratch {};
        for (int round = 0; round < 1000 && !captured; ++round) {
            const int result = SSL_read(client.get(), scratch.data(), scratch.size());
            if (result <= 0) {
                const int error = SSL_get_error(client.get(), result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    return {nullptr, SSL_SESSION_free};
            }
            server.write();
        }
        std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(
            captured, SSL_SESSION_free);
        if (!session || SSL_SESSION_is_resumable(session.get()) != 1)
            return {nullptr, SSL_SESSION_free};

        const int first_shutdown = SSL_shutdown(client.get());
        if (first_shutdown != 0 && first_shutdown != 1)
            return {nullptr, SSL_SESSION_free};
        for (int round = 0; round < 1000 && !server.read_eof(); ++round)
            server.read();
        if (!server.read_eof() || server.error() || transport->error())
            return {nullptr, SSL_SESSION_free};
        transport->shutdown(server.socket());
        if (SSL_shutdown(client.get()) != 1)
            return {nullptr, SSL_SESSION_free};
        return session;
    };

    bool first_reused = false;
    auto ticket = run_connection(nullptr, first_reused);
    ASSERT_NE(ticket, nullptr);
    EXPECT_FALSE(first_reused);

    bool second_reused = false;
    auto renewed_ticket = run_connection(ticket.get(), second_reused);
    ASSERT_NE(renewed_ticket, nullptr);
    EXPECT_TRUE(second_reused);
}

TEST_F(TLSIntegration, PeerCertificateRejectionTerminatesHandshakeWithoutRetryLoop) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    // Deliberately leave the trust store empty so the client emits a real
    // certificate-related fatal alert to the SSLCom server.
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_PEER, nullptr);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());

    bool client_failed = false;
    for (int round = 0; round < 1000 && !client_failed && !transport->error(); ++round) {
        const int result = SSL_connect(client.get());
        if (result != 1) {
            const int error = SSL_get_error(client.get(), result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                client_failed = true;
        }
        server.read();
    }
    EXPECT_TRUE(client_failed);
    EXPECT_TRUE(transport->error());
    EXPECT_FALSE(transport->com_status());

    const auto attempts = transport->counters.prof_accept_cnt;
    EXPECT_LE(server.read(), 0);
    EXPECT_LE(transport->counters.prof_accept_cnt, attempts + 1);
}

TEST_F(TLSIntegration, CorruptRecordAfterApplicationDataIsTerminal) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto* transport = new SSLCom();
    baseHostCX server(transport, sockets.release_first());
    server.auto_finish(false);
    server.opening(false);
    server.on_accept_socket(server.socket());
    ASSERT_FALSE(transport->error());

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION), 1);
    std::unique_ptr<SSL, ssl_ptr_deleter> client(SSL_new(client_ctx.get()));
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(SSL_set_fd(client.get(), sockets.second()), 1);
    SSL_set_connect_state(client.get());

    bool client_ready = false;
    for (int round = 0; round < 1000 &&
                            !(client_ready && transport->com_status()); ++round) {
        if (!client_ready) {
            const int result = SSL_connect(client.get());
            if (result == 1) {
                client_ready = true;
            } else {
                const int error = SSL_get_error(client.get(), result);
                ASSERT_TRUE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                    << "client handshake error=" << error;
            }
        }
        ASSERT_GE(server.read(), -1);
        ASSERT_FALSE(server.error());
    }
    ASSERT_TRUE(client_ready);

    const std::string payload = "valid-data-before-corrupt-record";
    ASSERT_EQ(SSL_write(client.get(), payload.data(), payload.size()),
              static_cast<int>(payload.size()));
    for (int round = 0; round < 1000 && server.readbuf()->size() < payload.size(); ++round)
        ASSERT_GE(server.read(), -1);
    ASSERT_EQ(server.readbuf()->size(), payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<char const*>(server.readbuf()->data()),
                          server.readbuf()->size()), payload);

    // Syntactically valid TLS 1.3 outer record carrying unauthenticated
    // ciphertext. OpenSSL must reject it as a terminal record-layer error.
    std::array<unsigned char, 21> corrupt_record {
        0x17, 0x03, 0x03, 0x00, 0x10,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    ASSERT_EQ(::send(sockets.second(), corrupt_record.data(), corrupt_record.size(),
                     MSG_NOSIGNAL), static_cast<ssize_t>(corrupt_record.size()));

    EXPECT_EQ(server.read(), 0);
    EXPECT_TRUE(transport->error());
    EXPECT_EQ(server.readbuf()->size(), payload.size());
    EXPECT_EQ(server.read(), 0);
}

TEST_F(TLSIntegration, ControlPathPerformanceTrace) {
    const char* configured = std::getenv("TLS_PERF_ITERATIONS");
    if (!configured)
        GTEST_SKIP() << "set TLS_PERF_ITERATIONS to enable the long trace benchmark";

    const int iterations = std::max(1, std::atoi(configured));
    const int threads = std::max(1, std::atoi(
        std::getenv("TLS_PERF_THREADS") ? std::getenv("TLS_PERF_THREADS") : "8"));
    using clock = std::chrono::steady_clock;
    auto milliseconds = [](clock::time_point start) {
        return std::chrono::duration<double, std::milli>(clock::now() - start).count();
    };

    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);
    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());

    auto started = clock::now();
    for (int i = 0; i < iterations; ++i) {
        const auto result = memory_handshake(spoofed->chain.cert, spoofed->chain.key,
                                             i & 1 ? TLS1_2_VERSION : TLS1_3_VERSION,
                                             true, 1, 1);
        ASSERT_TRUE(result.complete);
    }
    const double handshake_ms = milliseconds(started);
    std::cout << "TLS_PERF_STAGE memory_handshake " << handshake_ms << std::endl;

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> shared_ctx(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    ASSERT_NE(shared_ctx, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(shared_ctx.get(), spoofed->chain.cert), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(shared_ctx.get(), spoofed->chain.key), 1);

    std::vector<std::thread> workers;
    auto measure_ssl_new = [&](bool global_lock) {
        std::atomic<int> failures {0};
        auto phase_started = clock::now();
        for (int worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                for (int i = worker; i < iterations * threads; i += threads) {
                    SSL* ssl = nullptr;
                    if (global_lock) {
                        auto lock = std::scoped_lock(SSLFactory::factory().lock());
                        ssl = SSL_new(shared_ctx.get());
                    } else {
                        ssl = SSL_new(shared_ctx.get());
                    }
                    if (!ssl) {
                        ++failures;
                        continue;
                    }
                    SSL_free(ssl);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        workers.clear();
        return std::pair {milliseconds(phase_started), failures.load()};
    };

    const auto [global_ssl_new_ms, global_ssl_new_failures] = measure_ssl_new(true);
    std::cout << "TLS_PERF_STAGE global_ssl_new " << global_ssl_new_ms << std::endl;
    const auto [ssl_new_ms, ssl_new_failures] = measure_ssl_new(false);
    std::cout << "TLS_PERF_STAGE ssl_new " << ssl_new_ms << std::endl;
    EXPECT_EQ(global_ssl_new_failures, 0);
    EXPECT_EQ(ssl_new_failures, 0);

    auto measure_ssl_configuration = [&](bool groups) {
        std::atomic<int> failures {0};
        auto phase_started = clock::now();
        for (int worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                for (int i = worker; i < iterations * threads; i += threads) {
                    SSL* ssl = SSL_new(shared_ctx.get());
                    if (!ssl || SSL_set_cipher_list(ssl, SSLCom::ci_def_filter) != 1 ||
                        (groups && SSL_set1_groups_list(
                            ssl, "X25519:P-521:P-384:P-256:ffdhe2048") != 1)) {
                        ++failures;
                    }
                    if (ssl) SSL_free(ssl);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        workers.clear();
        return std::pair {milliseconds(phase_started), failures.load()};
    };

    const auto [ssl_cipher_ms, ssl_cipher_failures] = measure_ssl_configuration(false);
    std::cout << "TLS_PERF_STAGE ssl_new_cipher " << ssl_cipher_ms << std::endl;
    const auto [ssl_cipher_groups_ms, ssl_cipher_groups_failures] =
        measure_ssl_configuration(true);
    std::cout << "TLS_PERF_STAGE ssl_new_cipher_groups "
              << ssl_cipher_groups_ms << std::endl;
    EXPECT_EQ(ssl_cipher_failures, 0);
    EXPECT_EQ(ssl_cipher_groups_failures, 0);

    SpoofOptions cache_options;
    const std::string cache_key = SSLFactory::make_store_key(upstream.get(), cache_options);
    ASSERT_TRUE(SSLFactory::factory().add_mitm(cache_key, spoofed.value()));
    std::atomic<int> cache_failures {0};
    auto cache_started = clock::now();
    for (int worker = 0; worker < threads; ++worker) {
        workers.emplace_back([&, worker] {
            for (int i = worker; i < iterations * threads; i += threads) {
                if (!SSLFactory::factory().find_mitm(cache_key)) ++cache_failures;
            }
        });
    }
    for (auto& worker : workers) worker.join();
    workers.clear();
    const double cache_hit_ms = milliseconds(cache_started);
    std::cout << "TLS_PERF_STAGE cert_cache_hit " << cache_hit_ms << std::endl;
    EXPECT_EQ(cache_failures, 0);

    auto measure_hostname_check = [&](bool native) {
        std::atomic<int> failures {0};
        auto phase_started = clock::now();
        for (int worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                for (int i = worker; i < iterations * threads; i += threads) {
                    bool matched = false;
                    if (native) {
                        matched = X509_check_host(
                            upstream.get(), "Smithproxy-Server-Certificate", 0,
                            0, nullptr) == 1;
                    } else {
                        auto names = SSLFactory::get_sans(upstream.get());
                        names.push_back("DNS:" + SSLFactory::print_cn(upstream.get()));
                        for (auto& name : names) {
                            if (name.rfind("DNS:", 0) != 0) continue;
                            name.erase(0, 4);
                            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                            matched = name == "smithproxy-server-certificate";
                            if (matched) break;
                        }
                    }
                    if (!matched) ++failures;
                }
            });
        }
        for (auto& worker : workers) worker.join();
        workers.clear();
        return std::pair {milliseconds(phase_started), failures.load()};
    };

    const auto [manual_hostname_ms, manual_hostname_failures] =
        measure_hostname_check(false);
    const auto [native_hostname_ms, native_hostname_failures] =
        measure_hostname_check(true);
    std::cout << "TLS_PERF_STAGE hostname_manual " << manual_hostname_ms << std::endl;
    std::cout << "TLS_PERF_STAGE hostname_native " << native_hostname_ms << std::endl;
    EXPECT_EQ(manual_hostname_failures, 0);
    EXPECT_EQ(native_hostname_failures, 0);

    auto measure_certificate_retain = [&](bool deep_copy) {
        std::atomic<int> failures {0};
        auto phase_started = clock::now();
        for (int worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                for (int i = worker; i < iterations * threads; i += threads) {
                    X509* retained = nullptr;
                    if (deep_copy) {
                        retained = X509_dup(upstream.get());
                    } else if (X509_up_ref(upstream.get()) == 1) {
                        retained = upstream.get();
                    }
                    if (!retained) ++failures;
                    X509_free(retained);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        workers.clear();
        return std::pair {milliseconds(phase_started), failures.load()};
    };

    const auto [x509_dup_ms, x509_dup_failures] = measure_certificate_retain(true);
    const auto [x509_ref_ms, x509_ref_failures] = measure_certificate_retain(false);
    std::cout << "TLS_PERF_STAGE x509_dup " << x509_dup_ms << std::endl;
    std::cout << "TLS_PERF_STAGE x509_up_ref " << x509_ref_ms << std::endl;
    EXPECT_EQ(x509_dup_failures, 0);
    EXPECT_EQ(x509_ref_failures, 0);

    std::atomic<int> csr_failures {0};
    auto csr_started = clock::now();
    for (int worker = 0; worker < threads; ++worker) {
        workers.emplace_back([&, worker] {
            for (int i = worker; i < iterations * threads; i += threads) {
                auto csr = SSLFactory::factory().create_csr_from(upstream.get());
                if (!csr) {
                    ++csr_failures;
                } else {
                    X509_REQ_free(csr.value());
                }
            }
        });
    }
    for (auto& worker : workers) worker.join();
    workers.clear();
    const double csr_create_ms = milliseconds(csr_started);
    std::cout << "TLS_PERF_STAGE csr_create " << csr_create_ms << std::endl;
    EXPECT_EQ(csr_failures, 0);

    // Compare the old factory-wide critical section with the keyed locking
    // used by the production MITM path.  Calling the factory directly avoids
    // pulling connection-owned SSLMitmCom state into this microbenchmark.
    auto measure_spoof = [&](bool keyed_lock) {
        std::atomic<int> failures {0};
        auto phase_started = clock::now();
        for (int worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                for (int i = worker; i < iterations; i += threads) {
                    std::vector<std::string> sans {
                        "DNS:cold-" + std::to_string(i) + ".tls-perf.invalid"
                    };
                    const std::string& key = sans.front();
                    std::optional<CertificateChainCtx> generated;
                    if (keyed_lock) {
                        auto lock = std::scoped_lock(SSLFactory::factory().mitm_key_lock(key));
                        generated = SSLFactory::factory().spoof(upstream.get(), false, &sans);
                    } else {
                        auto lock = std::scoped_lock(SSLFactory::factory().lock());
                        generated = SSLFactory::factory().spoof(upstream.get(), false, &sans);
                    }
                    if (!generated) {
                        ++failures;
                        continue;
                    }
                    X509_free(generated->chain.cert);
                    generated->chain.cert = nullptr;
                }
            });
        }
        for (auto& worker : workers) worker.join();
        workers.clear();
        return std::pair {milliseconds(phase_started), failures.load()};
    };

    const auto [global_spoof_ms, global_spoof_failures] = measure_spoof(false);
    std::cout << "TLS_PERF_STAGE global_spoof " << global_spoof_ms << std::endl;
    const auto [keyed_spoof_ms, keyed_spoof_failures] = measure_spoof(true);
    std::cout << "TLS_PERF_STAGE keyed_spoof " << keyed_spoof_ms << std::endl;
    EXPECT_EQ(global_spoof_failures, 0);
    EXPECT_EQ(keyed_spoof_failures, 0);

    std::cout << "TLS_PERF {\"iterations\":" << iterations
              << ",\"threads\":" << threads
              << ",\"memory_handshake_ms\":" << handshake_ms
              << ",\"global_ssl_new_ms\":" << global_ssl_new_ms
              << ",\"ssl_new_ms\":" << ssl_new_ms
              << ",\"ssl_new_cipher_ms\":" << ssl_cipher_ms
              << ",\"ssl_new_cipher_groups_ms\":" << ssl_cipher_groups_ms
              << ",\"cert_cache_hit_ms\":" << cache_hit_ms
              << ",\"hostname_manual_ms\":" << manual_hostname_ms
              << ",\"hostname_native_ms\":" << native_hostname_ms
              << ",\"x509_dup_ms\":" << x509_dup_ms
              << ",\"x509_up_ref_ms\":" << x509_ref_ms
              << ",\"csr_create_ms\":" << csr_create_ms
              << ",\"global_spoof_ms\":" << global_spoof_ms
              << ",\"keyed_spoof_ms\":" << keyed_spoof_ms
              << ",\"global_ssl_new_failures\":" << global_ssl_new_failures
              << ",\"ssl_new_failures\":" << ssl_new_failures
              << ",\"global_spoof_failures\":" << global_spoof_failures
              << ",\"keyed_spoof_failures\":" << keyed_spoof_failures
              << "}" << std::endl;
}

TEST_F(TLSIntegration, SpoofPreservesIdentityAndUsesLocalCA) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);

    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());
    ASSERT_NE(spoofed->chain.cert, nullptr);
    ASSERT_NE(spoofed->chain.key, nullptr);

    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(upstream.get()),
                            X509_get_subject_name(spoofed->chain.cert)), 0);
    EXPECT_EQ(SSLFactory::get_sans(upstream.get()),
              SSLFactory::get_sans(spoofed->chain.cert));
    EXPECT_EQ(X509_check_private_key(spoofed->chain.cert, spoofed->chain.key), 1);

    auto ca = load_certificate(fixture_path_ / "ca-cert.pem");
    ASSERT_NE(ca, nullptr);
    EXPECT_EQ(X509_NAME_cmp(X509_get_issuer_name(spoofed->chain.cert),
                            X509_get_subject_name(ca.get())), 0);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ca_key(
        X509_get_pubkey(ca.get()), EVP_PKEY_free);
    ASSERT_NE(ca_key, nullptr);
    EXPECT_EQ(X509_verify(spoofed->chain.cert, ca_key.get()), 1);

    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, SpoofAddsRequestedSAN) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);
    std::vector<std::string> additional_sans = {"DNS:tls-test.smithproxy.invalid"};

    auto spoofed = SSLFactory::factory().spoof(upstream.get(), false, &additional_sans);
    ASSERT_TRUE(spoofed.has_value());
    const auto sans = SSLFactory::get_sans(spoofed->chain.cert);
    EXPECT_NE(std::find(sans.begin(), sans.end(), additional_sans.front()), sans.end());

    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, CertificateIpSansRoundTripThroughSpoof) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto upstream = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(upstream, nullptr);
    ASSERT_TRUE(add_certificate_extension(
        upstream.get(), issuer.get(), NID_subject_alt_name,
        "DNS:ip-san.test,IP:192.0.2.17,IP:2001:db8::17"));
    ASSERT_GT(X509_sign(upstream.get(), issuer_key.get(), EVP_sha256()), 0);

    const auto sans = SSLFactory::get_sans(upstream.get());
    EXPECT_NE(std::find(sans.begin(), sans.end(), "DNS:ip-san.test"), sans.end());
    EXPECT_NE(std::find(sans.begin(), sans.end(), "IP:192.0.2.17"), sans.end());
    EXPECT_NE(std::find(sans.begin(), sans.end(), "IP:2001:db8::17"), sans.end());

    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());
    ASSERT_NE(spoofed->chain.cert, nullptr);
    EXPECT_EQ(X509_check_ip_asc(spoofed->chain.cert, "192.0.2.17", 0), 1);
    EXPECT_EQ(X509_check_ip_asc(spoofed->chain.cert, "2001:db8::17", 0), 1);
    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, CustomCertificatesLoadFromFullchainAndSplitLayouts) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    auto key = load_private_key(fixture_path_ / "srv-key.pem");
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    const auto fullchain_dir = fixture_path_ / "sni" / "fullchain.test";
    const auto split_dir = fixture_path_ / "ip" / "192.0.2.44";
    std::filesystem::create_directories(fullchain_dir);
    std::filesystem::create_directories(split_dir);
    ASSERT_TRUE(write_certificate_file(fullchain_dir / "fullchain.pem",
                                       {certificate.get(), issuer.get()}));
    ASSERT_TRUE(write_private_key_file(fullchain_dir / "key.pem", key.get()));
    ASSERT_TRUE(write_certificate_file(split_dir / "cert.pem", {certificate.get()}));
    ASSERT_TRUE(write_certificate_file(split_dir / "issuer.pem", {issuer.get()}));
    ASSERT_TRUE(write_private_key_file(split_dir / "key.pem", key.get()));

    auto& factory = SSLFactory::factory();
    factory.cache_custom().clear();
    ASSERT_TRUE(factory.load_custom_certificates());

    const auto fullchain = factory.find_custom("sni:fullchain.test");
    ASSERT_TRUE(fullchain.has_value());
    ASSERT_NE(fullchain->ctx, nullptr);
    ASSERT_NE(fullchain->chain.cert, nullptr);
    ASSERT_NE(fullchain->chain.key, nullptr);
    EXPECT_EQ(X509_check_private_key(fullchain->chain.cert, fullchain->chain.key), 1);

    const auto split = factory.find_custom("ip:192.0.2.44");
    ASSERT_TRUE(split.has_value());
    ASSERT_NE(split->ctx, nullptr);
    ASSERT_NE(split->chain.cert, nullptr);
    ASSERT_NE(split->chain.key, nullptr);
    EXPECT_EQ(X509_check_private_key(split->chain.cert, split->chain.key), 1);
    EXPECT_NE(split->chain.issuers[2], nullptr);
}

TEST_F(TLSIntegration, SelfSignedSpoofUsesCopiedSubjectAndLocalKey) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);

    auto spoofed = SSLFactory::factory().spoof(upstream.get(), true);
    ASSERT_TRUE(spoofed.has_value());
    ASSERT_NE(spoofed->chain.cert, nullptr);
    ASSERT_NE(spoofed->chain.key, nullptr);

    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(upstream.get()),
                            X509_get_subject_name(spoofed->chain.cert)), 0);
    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(spoofed->chain.cert),
                            X509_get_issuer_name(spoofed->chain.cert)), 0);
    EXPECT_EQ(X509_check_private_key(spoofed->chain.cert, spoofed->chain.key), 1);
    EXPECT_EQ(X509_verify(spoofed->chain.cert, spoofed->chain.key), 1);

    X509_free(spoofed->chain.cert);
}

TEST_F(TLSIntegration, CRLReportsRevokedSerial) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), issuer_key.get(), certificate.get());
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), 1);
}

TEST_F(TLSIntegration, CRLReportsGoodSerial) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), issuer_key.get(), nullptr);
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), 0);
}

TEST_F(TLSIntegration, CRLTrustChecksCurrentGoodAndRevokedCertificates) {
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(issuer_key.get(), "CRL Test CA", nullptr,
                                           nullptr, 200, true);
    auto certificate = make_current_certificate(
        certificate_key.get(), "crl-leaf.test", issuer.get(), issuer_key.get(),
        201, false);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    const auto trust_path = fixture_path_ / "crl-current-ca.pem";
    FILE* trust_file = fopen(trust_path.c_str(), "w");
    ASSERT_NE(trust_file, nullptr);
    ASSERT_EQ(PEM_write_X509(trust_file, issuer.get()), 1);
    ASSERT_EQ(fclose(trust_file), 0);

    auto good_crl = make_crl(issuer.get(), issuer_key.get(), nullptr);
    auto revoked_crl = make_crl(issuer.get(), issuer_key.get(), certificate.get());
    ASSERT_NE(good_crl, nullptr);
    ASSERT_NE(revoked_crl, nullptr);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  certificate.get(), issuer.get(), good_crl.get(), trust_path.string()),
              1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  certificate.get(), issuer.get(), revoked_crl.get(), trust_path.string()),
              1);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(
                  certificate.get(), issuer.get(), good_crl.get()), 0);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(
                  certificate.get(), issuer.get(), revoked_crl.get()), 1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  certificate.get(), issuer.get(), good_crl.get(),
                  (fixture_path_ / "missing-ca.pem").string()),
              0);
}

TEST_F(TLSIntegration, CRLRejectsWrongIssuer) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto wrong_key = generate_rsa_key();
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(wrong_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), wrong_key.get(), certificate.get());
    ASSERT_NE(crl, nullptr);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(certificate.get(), issuer.get(), crl.get()), -1);
}

TEST_F(TLSIntegration, CRLCacheDropsExpiredEntries) {
    auto& cache = SSLFactory::factory().crl_cache();
    cache.clear();
    auto* entry = SSLFactory::make_expiring_crl(nullptr);
    entry->set_expiry(time(nullptr) - 1);
    cache.set("expired-crl", entry);

    EXPECT_EQ(cache.get("expired-crl"), nullptr);
    EXPECT_EQ(cache.size(), 0U);
    EXPECT_TRUE(cache.items().empty());
    cache.clear();
}

TEST_F(TLSIntegration, OCSPUrlsContainOnlyCertificateEntries) {
    auto certificate = upstream_certificate();
    ASSERT_NE(certificate, nullptr);
    X509V3_CTX context{};
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, nullptr, certificate.get(), nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr, &context, NID_info_access,
        const_cast<char*>("OCSP;URI:http://ocsp-one.invalid/status,"
                          "OCSP;URI:http://ocsp-two.invalid/status"));
    ASSERT_NE(extension, nullptr);
    ASSERT_EQ(X509_add_ext(certificate.get(), extension, -1), 1);
    X509_EXTENSION_free(extension);

    EXPECT_EQ(inet::ocsp::ocsp_urls(certificate.get()),
              (std::vector<std::string>{"http://ocsp-one.invalid/status",
                                        "http://ocsp-two.invalid/status"}));
}

TEST_F(TLSIntegration, OCSPMatchingEntryCannotBeOverriddenByDifferentCertificate) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    x509_ptr different_certificate(X509_dup(certificate.get()), X509_free);
    ASSERT_NE(different_certificate, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(different_certificate.get()), 0x123456), 1);

    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD},
         {different_certificate.get(), V_OCSP_CERTSTATUS_REVOKED}});
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);

    const auto result = inet::ocsp::ocsp_verify_response(
        response.get(), certificate.get(), issuer.get(), store.get());
    EXPECT_EQ(result.revoked, 0);
}

TEST_F(TLSIntegration, StapledOcspResponseVerifiesGoodAndRevokedStatus) {
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(issuer_key.get(), "Stapling Test CA", nullptr,
                                           nullptr, 300, true);
    auto certificate = make_current_certificate(
        certificate_key.get(), "stapled.test", issuer.get(), issuer_key.get(),
        301, false);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(SSLFactory::factory().trust_store(), issuer.get()), 1);

    for (const int status : {V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED}) {
        SCOPED_TRACE("OCSP status " + std::to_string(status));
        auto response = make_ocsp_response(
            issuer.get(), issuer_key.get(), {{certificate.get(), status}});
        ASSERT_NE(response, nullptr);
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
            SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
            context ? SSL_new(context.get()) : nullptr, SSL_free);
        ASSERT_NE(context, nullptr);
        ASSERT_NE(ssl, nullptr);
        ASSERT_TRUE(attach_ocsp_response(ssl.get(), response.get()));

        RevocationSSLCom connection;
        ASSERT_TRUE(connection.set_targets(certificate.get(), issuer.get()));
        connection.opt.ocsp.stapling_enabled = true;
        connection.opt.ocsp.stapling_mode = 2;
        const auto result = SSLCom::check_revocation_stapling(
            "stapled.test", &connection, ssl.get());
        EXPECT_EQ(result.first, SSLCom::staple_code_t::SUCCESS);
        EXPECT_EQ(result.second, status);
        EXPECT_FALSE(connection.opt.ocsp.enforce_in_verify);
    }
}

TEST_F(TLSIntegration, InvalidStapledOcspSignatureRequiresFailClosedFallback) {
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(issuer_key.get(), "Bad Stapling CA", nullptr,
                                           nullptr, 310, true);
    auto certificate = make_current_certificate(
        certificate_key.get(), "bad-stapled.test", issuer.get(), issuer_key.get(),
        311, false);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(SSLFactory::factory().trust_store(), issuer.get()), 1);

    auto valid_response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(valid_response, nullptr);
    OCSP_BASICRESP* basic = OCSP_response_get1_basic(valid_response.get());
    ASSERT_NE(basic, nullptr);
    const ASN1_OCTET_STRING* signature = OCSP_resp_get0_signature(basic);
    ASSERT_NE(signature, nullptr);
    ASSERT_GT(ASN1_STRING_length(signature), 0);
    auto* signature_data = const_cast<unsigned char*>(ASN1_STRING_get0_data(signature));
    signature_data[0] ^= 0x01;
    ocsp_response_ptr invalid_response(
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic), OCSP_RESPONSE_free);
    OCSP_BASICRESP_free(basic);
    ASSERT_NE(invalid_response, nullptr);

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        context ? SSL_new(context.get()) : nullptr, SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);
    ASSERT_TRUE(attach_ocsp_response(ssl.get(), invalid_response.get()));

    RevocationSSLCom connection;
    ASSERT_TRUE(connection.set_targets(certificate.get(), issuer.get()));
    connection.opt.ocsp.stapling_enabled = true;
    connection.opt.ocsp.stapling_mode = 1;
    connection.opt.cert.failed_check_replacement = false;
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);

    const auto parsed = SSLCom::check_revocation_stapling(
        "bad-stapled.test", &connection, ssl.get());
    EXPECT_EQ(parsed.first, SSLCom::staple_code_t::BASIC_VERIFY_FAILED);
    EXPECT_TRUE(connection.opt.ocsp.enforce_in_verify);
    connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_ALLFAILED));
}

using ocsp_parameters = std::tuple<int, int, int, int>;

class OCSPStatusMatrix : public TLSIntegration,
                         public ::testing::WithParamInterface<ocsp_parameters> {};

TEST_P(OCSPStatusMatrix, ReturnsStatusOnlyForCurrentSignedResponse) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    const auto [status, this_update_offset, next_update_offset, expected] = GetParam();
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(), {{certificate.get(), status}},
        this_update_offset, next_update_offset);
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);

    const auto result = inet::ocsp::ocsp_verify_response(
        response.get(), certificate.get(), issuer.get(), store.get());
    EXPECT_EQ(result.revoked, expected);
    EXPECT_GT(result.ttl, 0);
}

std::string ocsp_status_name(const ::testing::TestParamInfo<ocsp_parameters>& parameter) {
    switch (parameter.index) {
        case 0: return "Good";
        case 1: return "Revoked";
        case 2: return "Unknown";
        case 3: return "Expired";
        case 4: return "Future";
        default: return "Case" + std::to_string(parameter.index);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SignedResponses, OCSPStatusMatrix,
    ::testing::Values(
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, -60, 3600, 0},
        ocsp_parameters{V_OCSP_CERTSTATUS_REVOKED, -60, 3600, 1},
        ocsp_parameters{V_OCSP_CERTSTATUS_UNKNOWN, -60, 3600, -1},
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, -7200, -3600, -1},
        ocsp_parameters{V_OCSP_CERTSTATUS_GOOD, 3600, 7200, -1}),
    ocsp_status_name);

TEST_F(TLSIntegration, OCSPResponseForDifferentCertificateIsUnknown) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    x509_ptr different_certificate(X509_dup(certificate.get()), X509_free);
    ASSERT_NE(different_certificate, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(different_certificate.get()), 0x654321), 1);

    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{different_certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  response.get(), certificate.get(), issuer.get(), store.get()).revoked,
              -1);
}

TEST_F(TLSIntegration, OCSPRejectsNullAndResponderErrors) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(nullptr, certificate.get(), issuer.get()).revoked, -1);

    ocsp_response_ptr error_response(
        OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, nullptr), OCSP_RESPONSE_free);
    ASSERT_NE(error_response, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  error_response.get(), certificate.get(), issuer.get()).revoked,
              -1);
}

TEST_F(TLSIntegration, AsyncSocketCompletionKeepsTerminalStateAndForgetsBorrowedFd) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());
    baseHostCX owner(new TCPCom(), "192.0.2.1", "443");
    int callback_result = -1;
    CompletingAsyncSocket task(
        &owner, [&callback_result](int const& result) { callback_result = result; });

    task.tap(sockets.first(), false);
    ASSERT_EQ(task.state(), CompletingAsyncSocket::task_state_t::RUNNING);
    ASSERT_EQ(task.socket(), sockets.first());

    task.handle_event(owner.com());

    EXPECT_EQ(callback_result, 42);
    EXPECT_EQ(task.state(), CompletingAsyncSocket::task_state_t::FINISHED);
    EXPECT_EQ(task.socket(), 0);
    EXPECT_NE(fcntl(sockets.first(), F_GETFD), -1);
}

TEST_F(TLSIntegration, AsyncSocketTimeoutPublishesDerivedFailureBeforeCallback) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());
    baseHostCX owner(new TCPCom(), "192.0.2.1", "443");
    int callback_result = -1;
    TimeoutAsyncSocket task(
        &owner, [&callback_result](int const& result) { callback_result = result; });

    task.tap(sockets.first(), false);
    ASSERT_NE(owner.com()->poller.poller, nullptr);
    owner.com()->poller.poller->idle_set.insert(sockets.first());

    task.handle_event(owner.com());

    EXPECT_FALSE(task.update_called());
    EXPECT_EQ(callback_result, 24);
    EXPECT_EQ(task.state(), TimeoutAsyncSocket::task_state_t::TIMEOUT);
    EXPECT_EQ(task.socket(), 0);
    EXPECT_NE(fcntl(sockets.first(), F_GETFD), -1);
}

TEST_F(TLSIntegration, AsyncSocketRejectsInvalidRegistrationAndPollingStoresState) {
    baseHostCX owner(new TCPCom(), "192.0.2.1", "443");
    CompletingAsyncSocket task(&owner, nullptr);

    EXPECT_FALSE(task.tap(-1, false));
    EXPECT_FALSE(task.tap(0, false));
    EXPECT_EQ(task.state(), CompletingAsyncSocket::task_state_t::INIT);
    EXPECT_EQ(task.socket(), 0);

    EXPECT_TRUE(task.finished());
    EXPECT_EQ(task.state(), CompletingAsyncSocket::task_state_t::FINISHED);
    EXPECT_STREQ(task.state_str(), "FINISHED");

    CompletingAsyncSocket detached(nullptr, nullptr);
    EXPECT_FALSE(detached.tap(1, false));
    EXPECT_EQ(detached.state(), CompletingAsyncSocket::task_state_t::INIT);
}

TEST_F(TLSIntegration, OCSPRequestPreparationValidatesIssuer) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    OCSP_REQUEST* request = nullptr;
    STACK_OF(OCSP_CERTID)* ids = sk_OCSP_CERTID_new_null();
    ASSERT_NE(ids, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), EVP_sha1(), nullptr, ids), 0);
    EXPECT_EQ(request, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), EVP_sha1(), issuer.get(), ids), 1);
    ASSERT_NE(request, nullptr);
    EXPECT_EQ(sk_OCSP_CERTID_num(ids), 1);

    sk_OCSP_CERTID_free(ids);
    OCSP_REQUEST_free(request);
}

TEST_F(TLSIntegration, OCSPRequestPreparationRejectsIncompleteInputs) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    OCSP_REQUEST* request = nullptr;
    STACK_OF(OCSP_CERTID)* ids = sk_OCSP_CERTID_new_null();
    ASSERT_NE(ids, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  nullptr, certificate.get(), EVP_sha1(), issuer.get(), ids), 0);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, nullptr, EVP_sha1(), issuer.get(), ids), 0);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), nullptr, issuer.get(), ids), 0);
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), EVP_sha1(), issuer.get(), nullptr), 0);
    EXPECT_EQ(request, nullptr);
    EXPECT_EQ(sk_OCSP_CERTID_num(ids), 0);
    EXPECT_EQ(inet::ocsp::ocsp_check_bytes(nullptr, "issuer"), -1);
    EXPECT_EQ(inet::ocsp::ocsp_check_bytes("certificate", nullptr), -1);

    sk_OCSP_CERTID_free(ids);
}

TEST_F(TLSIntegration, SynchronousOCSPCheckCompletesAgainstLocalResponder) {
    static std::atomic<long> serial_seed {190};
    const long issuer_serial = serial_seed.fetch_add(2);
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    const std::string issuer_name = "Sync OCSP CA " + std::to_string(issuer_serial);
    auto issuer = make_current_certificate(issuer_key.get(), issuer_name.c_str(), nullptr,
                                           nullptr, issuer_serial, true);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(SSLFactory::factory().trust_store(), issuer.get()), 1);

    OneShotOcspResponder responder;
    ASSERT_TRUE(responder.valid());
    const std::string responder_url =
        "http://127.0.0.1:" + std::to_string(responder.port()) + "/status";
    auto certificate = make_current_certificate(
        certificate_key.get(), "sync-ocsp-leaf.test", issuer.get(),
        issuer_key.get(), issuer_serial + 1, false, responder_url);
    ASSERT_NE(certificate, nullptr);
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(response, nullptr);
    responder.reply_with(response.get());

    const auto status = inet::ocsp::ocsp_check_cert(
        certificate.get(), issuer.get(), 2);
    EXPECT_EQ(status.revoked, 0);
    EXPECT_GT(status.ttl, 0);
}

TEST_F(TLSIntegration, SynchronousOCSPIncludesNonDefaultPortInHostHeader) {
    static std::atomic<long> serial_seed {790};
    const long issuer_serial = serial_seed.fetch_add(2);
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(
        issuer_key.get(), "Host Header OCSP CA", nullptr, nullptr,
        issuer_serial, true);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(
                  SSLFactory::factory().trust_store(), issuer.get()), 1);

    OneShotOcspResponder responder;
    ASSERT_TRUE(responder.valid());
    const std::string responder_url =
        "http://127.0.0.1:" + std::to_string(responder.port()) + "/status";
    auto certificate = make_current_certificate(
        certificate_key.get(), "host-header-ocsp.test", issuer.get(),
        issuer_key.get(), issuer_serial + 1, false, responder_url);
    ASSERT_NE(certificate, nullptr);
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(response, nullptr);
    responder.reply_with_if_request_contains(
        response.get(),
        "Host: 127.0.0.1:" + std::to_string(responder.port()) + "\r\n");

    const auto status = inet::ocsp::ocsp_check_cert(
        certificate.get(), issuer.get(), 2);
    EXPECT_EQ(status.revoked, 0);
}

TEST_F(TLSIntegration, SynchronousOCSPBracketsIpv6HostAuthority) {
    static std::atomic<long> serial_seed {850};
    const long issuer_serial = serial_seed.fetch_add(2);
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(
        issuer_key.get(), "IPv6 Host OCSP CA", nullptr, nullptr,
        issuer_serial, true);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(
                  SSLFactory::factory().trust_store(), issuer.get()), 1);

    OneShotOcspResponder responder(AF_INET6);
    if (!responder.valid())
        GTEST_SKIP() << "IPv6 loopback is unavailable";
    const std::string responder_url =
        "http://[::1]:" + std::to_string(responder.port()) + "/status";
    auto certificate = make_current_certificate(
        certificate_key.get(), "ipv6-host-ocsp.test", issuer.get(),
        issuer_key.get(), issuer_serial + 1, false, responder_url);
    ASSERT_NE(certificate, nullptr);
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(response, nullptr);
    responder.reply_with_if_request_contains(
        response.get(),
        "Host: [::1]:" + std::to_string(responder.port()) + "\r\n");

    const auto status = inet::ocsp::ocsp_check_cert(
        certificate.get(), issuer.get(), 2);
    EXPECT_EQ(status.revoked, 0);
}

TEST_F(TLSIntegration, SynchronousOCSPAcceptsSocketDescriptorZero) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    OCSP_REQUEST* request = nullptr;
    STACK_OF(OCSP_CERTID)* ids = sk_OCSP_CERTID_new_null();
    ASSERT_NE(ids, nullptr);
    ASSERT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), EVP_sha1(), issuer.get(), ids), 1);
    ASSERT_NE(request, nullptr);

    OneShotOcspResponder responder;
    ASSERT_TRUE(responder.valid());
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(response, nullptr);
    responder.reply_with(response.get());

    const int saved_stdin = ::dup(STDIN_FILENO);
    ASSERT_GE(saved_stdin, 0);
    ASSERT_EQ(::close(STDIN_FILENO), 0);
    std::string port = std::to_string(responder.port());
    char host[] = "127.0.0.1";
    char path[] = "/status";
    OCSP_RESPONSE* received = inet::ocsp::ocsp_send_request(
        nullptr, request, host, path, port.data(), 0, 2);
    const int restore_result = ::dup2(saved_stdin, STDIN_FILENO);
    ::close(saved_stdin);

    ASSERT_EQ(restore_result, STDIN_FILENO);
    ASSERT_NE(received, nullptr);
    EXPECT_EQ(OCSP_response_status(received), OCSP_RESPONSE_STATUS_SUCCESSFUL);
    OCSP_RESPONSE_free(received);
    sk_OCSP_CERTID_free(ids);
    OCSP_REQUEST_free(request);
}

TEST_F(TLSIntegration, SynchronousOCSPTimeoutIsOneEndToEndDeadline) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    OCSP_REQUEST* request = nullptr;
    STACK_OF(OCSP_CERTID)* ids = sk_OCSP_CERTID_new_null();
    ASSERT_NE(ids, nullptr);
    ASSERT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, certificate.get(), EVP_sha1(), issuer.get(), ids), 1);
    ASSERT_NE(request, nullptr);

    OneShotOcspResponder responder;
    ASSERT_TRUE(responder.valid());
    responder.reply_in_chunks(
        "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n"
        "Content-Length: 8\r\n\r\n12345678",
        std::chrono::milliseconds(300), 1);
    std::string port = std::to_string(responder.port());
    char host[] = "127.0.0.1";
    char path[] = "/status";

    const auto started = std::chrono::steady_clock::now();
    OCSP_RESPONSE* response = inet::ocsp::ocsp_send_request(
        nullptr, request, host, path, port.data(), 0, 1);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    EXPECT_EQ(response, nullptr);
    EXPECT_GE(elapsed.count(), 700);
    EXPECT_LT(elapsed.count(), 1600);
    OCSP_RESPONSE_free(response);
    sk_OCSP_CERTID_free(ids);
    OCSP_REQUEST_free(request);
}

TEST_F(TLSIntegration, SynchronousOCSPTimeoutCoversAllResponderUrls) {
    static std::atomic<long> serial_seed {900};
    const long issuer_serial = serial_seed.fetch_add(2);
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    auto issuer = make_current_certificate(
        issuer_key.get(), "Multi URL OCSP CA", nullptr, nullptr,
        issuer_serial, true);
    ASSERT_NE(issuer, nullptr);

    OneShotOcspResponder first;
    OneShotOcspResponder second;
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(second.valid());
    const std::string first_url =
        "http://127.0.0.1:" + std::to_string(first.port()) + "/first";
    const std::string second_url =
        "http://127.0.0.1:" + std::to_string(second.port()) + "/second";
    auto certificate = make_current_certificate(
        certificate_key.get(), "multi-url-ocsp.test", issuer.get(),
        issuer_key.get(), issuer_serial + 1, false,
        first_url + ",OCSP;URI:" + second_url);
    ASSERT_NE(certificate, nullptr);
    ASSERT_EQ(inet::ocsp::ocsp_urls(certificate.get()).size(), 2U);

    const std::string malformed_reply =
        "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n"
        "Content-Length: 1\r\n\r\nX";
    first.reply_after(malformed_reply, std::chrono::milliseconds(800));
    second.reply_after(malformed_reply, std::chrono::milliseconds(800));

    const auto started = std::chrono::steady_clock::now();
    const auto status = inet::ocsp::ocsp_check_cert(
        certificate.get(), issuer.get(), 1);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    EXPECT_EQ(status.revoked, -1);
    EXPECT_GE(elapsed.count(), 700);
    EXPECT_LT(elapsed.count(), 1400);
}

TEST_F(TLSIntegration, SynchronousOCSPRejectsTrailingResponseData) {
    static std::atomic<long> serial_seed {500};
    const long issuer_serial = serial_seed.fetch_add(2);
    auto issuer_key = generate_rsa_key();
    auto certificate_key = generate_rsa_key();
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    const std::string issuer_name =
        "Trailing OCSP CA " + std::to_string(issuer_serial);
    auto issuer = make_current_certificate(
        issuer_key.get(), issuer_name.c_str(), nullptr, nullptr,
        issuer_serial, true);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(SSLFactory::factory().trust_store(), nullptr);
    ASSERT_EQ(X509_STORE_add_cert(
                  SSLFactory::factory().trust_store(), issuer.get()), 1);

    OneShotOcspResponder responder;
    ASSERT_TRUE(responder.valid());
    const std::string responder_url =
        "http://127.0.0.1:" + std::to_string(responder.port()) + "/status";
    auto certificate = make_current_certificate(
        certificate_key.get(), "trailing-ocsp.test", issuer.get(),
        issuer_key.get(), issuer_serial + 1, false, responder_url);
    ASSERT_NE(certificate, nullptr);
    auto response = make_ocsp_response(
        issuer.get(), issuer_key.get(),
        {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(response, nullptr);
    responder.reply_with_trailing_byte(response.get());

    const auto status = inet::ocsp::ocsp_check_cert(
        certificate.get(), issuer.get(), 2);
    EXPECT_EQ(status.revoked, -1);
}

TEST_F(TLSIntegration, CRLDerParsersRoundTripAndRejectEmptyInput) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);
    auto crl = make_crl(issuer.get(), issuer_key.get(), certificate.get());
    ASSERT_NE(crl, nullptr);

    const int encoded_size = i2d_X509_CRL(crl.get(), nullptr);
    ASSERT_GT(encoded_size, 0);
    std::vector<unsigned char> encoded(static_cast<std::size_t>(encoded_size));
    unsigned char* output = encoded.data();
    ASSERT_EQ(i2d_X509_CRL(crl.get(), &output), encoded_size);

    buffer encoded_buffer;
    encoded_buffer.append(encoded.data(), encoded.size());
    crl_ptr parsed_buffer(inet::crl::crl_from_bytes(encoded_buffer), X509_CRL_free);
    ASSERT_NE(parsed_buffer, nullptr);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(
                  certificate.get(), issuer.get(), parsed_buffer.get()), 1);

    const auto der_path = fixture_path_ / "roundtrip.crl.der";
    FILE* file = fopen(der_path.c_str(), "wb");
    ASSERT_NE(file, nullptr);
    ASSERT_EQ(fwrite(encoded.data(), 1, encoded.size(), file), encoded.size());
    ASSERT_EQ(fclose(file), 0);
    crl_ptr parsed_file(inet::crl::crl_from_file(der_path.c_str()), X509_CRL_free);
    ASSERT_NE(parsed_file, nullptr);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(
                  certificate.get(), issuer.get(), parsed_file.get()), 1);

    buffer empty;
    EXPECT_EQ(inet::crl::crl_from_bytes(empty), nullptr);
    EXPECT_EQ(inet::crl::crl_from_bytes(static_cast<const char*>(nullptr)), nullptr);
    EXPECT_EQ(inet::crl::crl_from_file(nullptr), nullptr);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(nullptr, issuer.get(), crl.get()), -1);
    EXPECT_EQ(inet::crl::crl_verify_trust(nullptr, issuer.get(), crl.get(), {}), 0);
    EXPECT_TRUE(inet::crl::crl_urls(nullptr).empty());
    EXPECT_TRUE(inet::ocsp::ocsp_urls(nullptr).empty());
}

TEST_F(TLSIntegration, CertificateDiagnosticsRejectMissingObjectsSafely) {
    EXPECT_TRUE(SSLFactory::get_sans(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_cn(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_issuer(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_not_before(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_not_after(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_ASN1_OCTET_STRING(nullptr).empty());

    std::array<char, 16> output{};
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(nullptr, output.data(), output.size()),
              EXIT_FAILURE);
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(nullptr, nullptr, 0), EXIT_FAILURE);
}

TEST_F(TLSIntegration, OCSPRejectsResponseWithWrongSignature) {
    auto issuer = load_certificate(fixture_path_ / "ca-cert.pem");
    auto issuer_key = load_private_key(fixture_path_ / "ca-key.pem");
    auto certificate = upstream_certificate();
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate, nullptr);

    auto valid_response = make_ocsp_response(
        issuer.get(), issuer_key.get(), {{certificate.get(), V_OCSP_CERTSTATUS_GOOD}});
    ASSERT_NE(valid_response, nullptr);
    OCSP_BASICRESP* basic = OCSP_response_get1_basic(valid_response.get());
    ASSERT_NE(basic, nullptr);
    const ASN1_OCTET_STRING* signature = OCSP_resp_get0_signature(basic);
    ASSERT_NE(signature, nullptr);
    ASSERT_GT(ASN1_STRING_length(signature), 0);
    auto* signature_data = const_cast<unsigned char*>(ASN1_STRING_get0_data(signature));
    signature_data[0] ^= 0x01;
    ocsp_response_ptr response(
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic), OCSP_RESPONSE_free);
    OCSP_BASICRESP_free(basic);
    auto store = make_test_store(issuer.get());
    ASSERT_NE(response, nullptr);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  response.get(), certificate.get(), issuer.get(), store.get()).revoked,
              -1);
}

using handshake_parameters = std::tuple<int, bool, int, std::size_t>;

class TLSHandshakeMatrix : public TLSIntegration,
                           public ::testing::WithParamInterface<handshake_parameters> {};

std::string handshake_name(
    const ::testing::TestParamInfo<handshake_parameters>& parameter) {
    const auto [version, send_sni, alpn_mode, payload_size] = parameter.param;
    static constexpr const char* alpn_names[] = {"NoALPN", "H2First", "HTTP1Only", "HTTP1First"};
    return std::string(version == TLS1_3_VERSION ? "TLS13" : "TLS12") +
           (send_sni ? "_SNI_" : "_NoSNI_") + alpn_names[alpn_mode] +
           "_Payload" + std::to_string(payload_size);
}

TEST_P(TLSHandshakeMatrix, SpoofedCertificateCompletesNegotiationAndDataTransfer) {
    auto upstream = upstream_certificate();
    ASSERT_NE(upstream, nullptr);
    auto spoofed = SSLFactory::factory().spoof(upstream.get());
    ASSERT_TRUE(spoofed.has_value());

    const auto [version, send_sni, alpn_mode, payload_size] = GetParam();
    const auto result = memory_handshake(spoofed->chain.cert, spoofed->chain.key,
                                         version, send_sni, alpn_mode, payload_size);
    EXPECT_TRUE(result.complete);
    EXPECT_EQ(result.sni, send_sni ? "tls-test.smithproxy.invalid" : "");
    EXPECT_EQ(result.alpn, alpn_mode == 1 || alpn_mode == 3 ? "h2" : "");
    EXPECT_TRUE(result.application_data_ok);

    X509_free(spoofed->chain.cert);
}

INSTANTIATE_TEST_SUITE_P(
    TLS12AndTLS13, TLSHandshakeMatrix,
    ::testing::Combine(
        ::testing::Values(TLS1_2_VERSION, TLS1_3_VERSION),
        ::testing::Bool(),
        ::testing::Values(0, 1, 2, 3),
        ::testing::Values(std::size_t{0}, std::size_t{1}, std::size_t{4096})),
    handshake_name);

} // namespace
