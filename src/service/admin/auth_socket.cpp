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
    if(probe < 0) {
        return true;
    }

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

bool secure_socket_directory(const std::filesystem::path& directory) {
    struct stat metadata {};
    if(::lstat(directory.c_str(), &metadata) != 0) {
        if(errno != ENOENT) {
            return false;
        }

        std::error_code error;
        const bool created = std::filesystem::create_directories(directory, error);
        const bool directory_available =
            created || std::filesystem::is_directory(directory, error);
        if(error || !directory_available) {
            return false;
        }

        const bool permissions_set = ::chmod(directory.c_str(), 0750) == 0;
        const bool metadata_loaded =
            permissions_set && ::lstat(directory.c_str(), &metadata) == 0;
        if(!metadata_loaded) {
            return false;
        }
    }

    const bool directory_entry = S_ISDIR(metadata.st_mode);
    const bool trusted_owner = metadata.st_uid == ::geteuid();
    const bool trusted_group = metadata.st_gid == ::getegid();
    const bool safe_mode = (metadata.st_mode & 0022) == 0;
    return directory_entry && trusted_owner && trusted_group && safe_mode;
}

} // namespace

namespace sx::admin {

AuthSocket::AuthSocket(std::filesystem::path path, Authenticate authenticate, Log log):
    path_(std::move(path)),
    authenticate_(std::move(authenticate)),
    log_(std::move(log)) {}

AuthSocket::~AuthSocket() { stop(); }

void AuthSocket::report(const bool warning, const std::string_view message) const {
    if(log_) {
        log_(warning, message);
    }
}

bool AuthSocket::start() {
    if(worker_.joinable()) {
        return running();
    }

    const auto path = path_.string();
    const bool valid_path = path_.is_absolute() && !path.empty() &&
        path.size() < sizeof(sockaddr_un::sun_path) &&
        path.find('\0') == std::string::npos;
    if(!valid_path || !authenticate_) {
        report(true, "administrator authentication socket configuration is invalid");
        return false;
    }

    if(!secure_socket_directory(path_.parent_path())) {
        report(true, "administrator authentication socket directory is unsafe or unavailable");
        return false;
    }

    // Never replace an active or foreign filesystem entry. A stale socket may
    // be reclaimed only when it is owned by this Core identity.
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
    // Publish the endpoint with group access for trusted Smithproxy components,
    // then remember its inode identity for safe cleanup.
    const bool bound = ::bind(
        listener, reinterpret_cast<const sockaddr*>(&address), address_size) == 0;
    const bool permissions_set = bound && ::chmod(path.c_str(), 0660) == 0;
    const bool listening = permissions_set && ::listen(listener, 16) == 0;
    struct stat published {};
    const bool published_ok = listening && ::lstat(path.c_str(), &published) == 0 &&
        S_ISSOCK(published.st_mode) && published.st_uid == ::geteuid() &&
        published.st_gid == ::getegid() && (published.st_mode & 0777) == 0660;
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

    if(worker_.joinable()) {
        worker_.join();
    }

    running_.store(false);
    remove_owned_socket();
}

bool AuthSocket::remove_owned_socket() const noexcept {
    // Path ownership alone is insufficient: avoid unlinking a replacement
    // socket created by another process after this listener stopped.
    struct stat current {};
    if(::lstat(path_.c_str(), &current) != 0) {
        return errno == ENOENT;
    }

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
            if(retryable) {
                continue;
            }

            if(!stopping_.load()) {
                report(true, "administrator authentication socket accept failed");
            }

            break;
        }

        serve_client(client);
        ::close(client);
    }
    running_.store(false);
}

void AuthSocket::serve_client(const int descriptor) noexcept {
    // Peer credentials bind throttling and audit identity to the local UID;
    // no caller-controlled source string crosses this transport boundary.
    const bool receive_timeout_set = ::setsockopt(
        descriptor, SOL_SOCKET, SO_RCVTIMEO,
        &client_timeout, sizeof(client_timeout)) == 0;
    const bool send_timeout_set = ::setsockopt(
        descriptor, SOL_SOCKET, SO_SNDTIMEO,
        &client_timeout, sizeof(client_timeout)) == 0;
    const bool timeouts_set = receive_timeout_set && send_timeout_set;
    if(!timeouts_set) {
        return;
    }

    struct ucred peer {};
    socklen_t peer_size = sizeof(peer);
    const bool peer_known = ::getsockopt(
        descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) == 0 &&
        peer_size == sizeof(peer);
    if(!peer_known) {
        return;
    }

    // SOCK_SEQPACKET preserves one request boundary. MSG_TRUNC rejects an
    // oversized packet instead of accepting a valid-looking prefix.
    std::array<char, maximum_request_size> buffer {};
    const auto received = ::recv(descriptor, buffer.data(), buffer.size(), MSG_TRUNC);
    const bool bounded_request = received > 0 &&
        static_cast<std::size_t>(received) <= buffer.size();
    // Keep malformed and exceptional paths indistinguishable to callers.
    nlohmann::json response{{"version", protocol_version}, {"status", "invalid_request"}};
    bool valid_request = false;

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
                auto& parsed_password = request["password"].get_ref<std::string&>();
                Secret password{parsed_password};
                if(!parsed_password.empty()) {
                    OPENSSL_cleanse(parsed_password.data(), parsed_password.size());
                }

                parsed_password.clear();

                const bool valid_lengths = !username.empty() && username.size() <= 255U &&
                    !password.value.empty() && password.value.size() <= 1024U;
                if(valid_lengths) {
                    valid_request = true;
                    response = response_for(authenticate_(
                        peer_source(peer), username, password.value));
                }
            }
        }
        catch(...) {
            valid_request = false;
        }
    }

    if(!valid_request) {
        invalid_requests_.fetch_add(1U);
    }

    OPENSSL_cleanse(buffer.data(), buffer.size());

    const auto payload = response.dump();
    const auto sent = ::send(descriptor, payload.data(), payload.size(), MSG_NOSIGNAL);
    (void)sent;
}

} // namespace sx::admin
