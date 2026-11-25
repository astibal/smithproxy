#include "auth_socket.hpp"

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <system_error>
#include <utility>

namespace {

constexpr std::size_t maximum_request_size = 4096U;
constexpr int protocol_version = 1;
constexpr struct timeval client_timeout {2, 0};

struct Secret {
    std::string value;

    ~Secret() {
        if(!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

std::string peer_source(const struct ucred& peer) {
    return "unix:uid=" + std::to_string(peer.uid);
}

nlohmann::json response_for(const sx::admin::LoginResult& result) {
    using Status = sx::admin::LoginStatus;
    nlohmann::json response{{"version", protocol_version}};
    switch(result.status) {
        case Status::accepted:
            response["status"] = "accepted";
            response["identity"] = result.identity;
            response["authentication_method"] = result.authentication_method;
            break;
        case Status::rejected:
            response["status"] = "rejected";
            break;
        case Status::throttled:
            response["status"] = "throttled";
            response["retry_after_seconds"] = result.retry_after_seconds;
            break;
        case Status::unavailable:
            response["status"] = "unavailable";
            break;
    }
    return response;
}

bool active_socket(const std::string& path) {
    const int probe = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(probe < 0) return true;
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    const auto address_size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    const bool connected = ::connect(
        probe, reinterpret_cast<const sockaddr*>(&address), address_size) == 0;
    const int connection_error = errno;
    ::close(probe);
    return connected || connection_error != ECONNREFUSED;
}

} // namespace

namespace sx::admin {

AuthSocket::AuthSocket(
    std::filesystem::path path,
    Authenticate authenticate,
    Log log)
    : path_(std::move(path)),
      authenticate_(std::move(authenticate)),
      log_(std::move(log)) {}

AuthSocket::~AuthSocket() { stop(); }

void AuthSocket::report(const bool warning, const std::string_view message) const {
    if(log_) log_(warning, message);
}

bool AuthSocket::start() {
    if(worker_.joinable()) return running();
    const auto path = path_.string();
    const bool valid_path = path_.is_absolute() && !path.empty() &&
        path.size() < sizeof(sockaddr_un::sun_path) &&
        path.find('\0') == std::string::npos;
    if(!valid_path || !authenticate_) {
        report(true, "administrator authentication socket configuration is invalid");
        return false;
    }

    std::error_code directory_error;
    std::filesystem::create_directories(path_.parent_path(), directory_error);
    if(directory_error) {
        report(true, "administrator authentication socket directory is unavailable");
        return false;
    }

    struct stat existing {};
    if(::lstat(path.c_str(), &existing) == 0) {
        const bool owned_socket = S_ISSOCK(existing.st_mode) &&
            existing.st_uid == ::geteuid();
        const bool replaceable = owned_socket && !active_socket(path);
        if(!replaceable || ::unlink(path.c_str()) != 0) {
            report(true, "administrator authentication socket path is occupied");
            return false;
        }
    }
    else if(errno != ENOENT) {
        report(true, "administrator authentication socket path cannot be inspected");
        return false;
    }

    const int listener = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if(listener < 0) {
        report(true, "administrator authentication socket cannot be created");
        return false;
    }

    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    const auto address_size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    const bool bound = ::bind(
        listener, reinterpret_cast<const sockaddr*>(&address), address_size) == 0;
    const bool permissions_set = bound && ::chmod(path.c_str(), 0660) == 0;
    const bool listening = permissions_set && ::listen(listener, 16) == 0;
    struct stat published {};
    const bool published_ok = listening && ::lstat(path.c_str(), &published) == 0 &&
        S_ISSOCK(published.st_mode);
    if(!published_ok) {
        ::close(listener);
        if(bound) ::unlink(path.c_str());
        report(true, "administrator authentication socket cannot be published");
        return false;
    }

    socket_device_ = published.st_dev;
    socket_inode_ = published.st_ino;
    listener_.store(listener);
    stopping_.store(false);
    running_.store(true);
    worker_ = std::thread([this] { serve(); });
    return true;
}

void AuthSocket::stop() noexcept {
    stopping_.store(true);
    const int listener = listener_.exchange(-1);
    if(listener >= 0) {
        ::shutdown(listener, SHUT_RDWR);
        ::close(listener);
    }
    if(worker_.joinable()) worker_.join();
    running_.store(false);
    remove_owned_socket();
}

bool AuthSocket::remove_owned_socket() const noexcept {
    struct stat current {};
    if(::lstat(path_.c_str(), &current) != 0) return errno == ENOENT;
    const bool same_socket = S_ISSOCK(current.st_mode) &&
        current.st_dev == socket_device_ && current.st_ino == socket_inode_;
    return same_socket && ::unlink(path_.c_str()) == 0;
}

void AuthSocket::serve() noexcept {
    const int listener = listener_.load();
    while(!stopping_.load()) {
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if(client < 0) {
            const bool retryable = errno == EINTR;
            if(retryable) continue;
            if(!stopping_.load())
                report(true, "administrator authentication socket accept failed");
            break;
        }
        serve_client(client);
        ::close(client);
    }
    running_.store(false);
}

void AuthSocket::serve_client(const int descriptor) noexcept {
    const bool receive_timeout_set = ::setsockopt(
        descriptor, SOL_SOCKET, SO_RCVTIMEO,
        &client_timeout, sizeof(client_timeout)) == 0;
    const bool send_timeout_set = ::setsockopt(
        descriptor, SOL_SOCKET, SO_SNDTIMEO,
        &client_timeout, sizeof(client_timeout)) == 0;
    if(!receive_timeout_set || !send_timeout_set) return;

    struct ucred peer {};
    socklen_t peer_size = sizeof(peer);
    const bool peer_known = ::getsockopt(
        descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
        peer_size == sizeof(peer);
    if(!peer_known) return;

    std::array<char, maximum_request_size> buffer {};
    const auto received = ::recv(descriptor, buffer.data(), buffer.size(), MSG_TRUNC);
    const bool bounded_request = received > 0 &&
        static_cast<std::size_t>(received) <= buffer.size();
    nlohmann::json response{{"version", protocol_version}, {"status", "invalid_request"}};
    if(bounded_request) {
        try {
            auto request = nlohmann::json::parse(
                buffer.data(), buffer.data() + received);
            const bool valid_envelope = request.is_object() &&
                request.value("version", 0) == protocol_version &&
                request.value("operation", std::string{}) == "authenticate" &&
                request.contains("username") && request["username"].is_string() &&
                request.contains("password") && request["password"].is_string();
            if(valid_envelope) {
                const auto username = request["username"].get<std::string>();
                Secret password{
                    std::move(request["password"].get_ref<std::string&>())};
                const bool valid_lengths = !username.empty() && username.size() <= 255U &&
                    !password.value.empty() && password.value.size() <= 1024U;
                if(valid_lengths) {
                    response = response_for(authenticate_(
                        peer_source(peer), username, password.value));
                }
            }
        }
        catch(...) {
            // The fixed invalid_request response deliberately reveals no parser detail.
        }
    }
    OPENSSL_cleanse(buffer.data(), buffer.size());

    const auto payload = response.dump();
    const auto sent = ::send(descriptor, payload.data(), payload.size(), MSG_NOSIGNAL);
    (void)sent;
}

} // namespace sx::admin
