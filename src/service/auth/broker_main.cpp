#include "pam_backend.hpp"

#include <cstring>
#include <lmhttpd.hpp>
#include <libconfig.h++>
#include <nlohmann/json.hpp>

#include <csignal>
#include <iostream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

namespace {
volatile std::sig_atomic_t stopped = 0;
void stop(int) { stopped = 1; }

class Listener {
public:
    explicit Listener(std::string path) : path_(std::move(path)) {
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if(path_.empty() || path_.front() != '/' || path_.size() >= sizeof(address.sun_path) ||
           path_.find('\0') != std::string::npos) {
            throw std::runtime_error("socket must be an absolute Unix socket path");
        }
        std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
        fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if(fd_ < 0) {
            throw std::runtime_error("cannot create authentication socket");
        }

        // Do not unlink a stale or live path supplied by another process.
        // The owner must resolve it explicitly before restarting the daemon.
        if(::bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            ::close(fd_);
            throw std::runtime_error("cannot bind authentication socket; path may already exist");
        }
        struct stat status{};
        if(::lstat(path_.c_str(), &status) == 0) {
            inode_ = status.st_ino;
            device_ = status.st_dev;
        }
        if(::listen(fd_, 64) != 0) {
            close();
            throw std::runtime_error("cannot listen on authentication socket");
        }
    }
    ~Listener() { close(); }
    int descriptor() const { return fd_; }
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

private:
    void close() {
        if(fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        struct stat status{};
        if(::lstat(path_.c_str(), &status) == 0 && S_ISSOCK(status.st_mode) &&
           status.st_ino == inode_ && status.st_dev == device_) {
            ::unlink(path_.c_str());
        }
    }
    std::string path_;
    int fd_ = -1;
    ino_t inode_ = 0;
    dev_t device_ = 0;
};

class PapController final : public lmh::DynamicController {
public:
    explicit PapController(sx::auth::PapBackend& backend) : backend_(backend) {}
    bool validPath(const char* path, const char* method) override {
        return std::strcmp(path, "/v1/pap") == 0 && std::strcmp(method, "POST") == 0;
    }
    lmh::ResponseParams createResponse(MHD_Connection*, const char*, const char*,
            const char* data, std::size_t* size, void** state_pointer, std::stringstream& output) override {
        auto& state = *static_cast<lmh::ConnectionState*>(*state_pointer);
        lmh::ResponseParams response;
        response.headers = {{"Content-Type", "application/json"}, {"Cache-Control", "no-store"}};
        if(*size != 0) {
            if(state.response_code != 413 && *size <= 4096 - state.request_data.size()) {
                state.request_data.append(data, *size);
            } else {
                state.response_code = 413;
                state.request_data.clear();
            }
            *size = 0;
            return response;
        }
        if(state.response_code == 413) {
            response.response_code = 413;
            output << R"({"version":1,"status":"error"})";
            return response;
        }

        try {
            const auto request = nlohmann::json::parse(state.request_data);
            if(!request.is_object() || request.size() != 3 || request.at("version") != 1) {
                throw std::runtime_error("invalid request");
            }
            sx::auth::PapCredentials credentials{
                request.at("username").get<std::string>(), request.at("password").get<std::string>()};
            state.request_data.clear();
            auto result = backend_.verify_pap(std::move(credentials), {});
            if(!result || result->status == sx::auth::PapStatus::error) {
                response.response_code = 503;
                output << R"({"version":1,"status":"error"})";
            } else if(result->status == sx::auth::PapStatus::rejected) {
                output << R"({"version":1,"status":"rejected"})";
            } else {
                output << nlohmann::json{{"version", 1}, {"status", "accepted"},
                    {"identity", result->identity}, {"groups", result->groups}}.dump();
            }
        } catch(...) {
            response.response_code = 400;
            output << R"({"version":1,"status":"error"})";
        }
        return response;
    }
private:
    sx::auth::PapBackend& backend_;
};
}

int main(int argc, char** argv) {
    if(argc != 3 || std::string_view(argv[1]) != "--config") {
        std::cerr << "Usage: smithproxy-auth-broker --config <libconfig file>\n";
        return 2;
    }
    try {
        libconfig::Config config;
        config.readFile(argv[2]);
        const std::string socket_path = config.lookup("socket");
        const std::string service = config.lookup("pam.service");
        const std::string group = config.lookup("pam.allowed_group");
        std::string config_directory;
        config.lookupValue("pam.config_directory", config_directory);
        sx::auth::LinuxPamBackend backend(service, group, config_directory);

        // Only the daemon's user can access credentials on this prototype
        // socket. Deploy both processes with a deliberate shared identity.
        ::umask(0077);
        Listener listener(socket_path);
        std::signal(SIGTERM, stop);
        std::signal(SIGINT, stop);
        lmh::WebServer server(0);
        server.options().listen_socket = listener.descriptor();
        server.options().handler_should_terminate = [] { return stopped != 0; };
        server.addController(std::make_shared<PapController>(backend));
        return server.start() ? 0 : 1;
    } catch(const libconfig::ConfigException&) {
        std::cerr << "Invalid authentication broker configuration\n";
    } catch(const std::exception& error) {
        std::cerr << error.what() << '\n';
    }
    return 1;
}
