#include <service/privileged_file.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstring>
#include <filesystem>
#include <limits>
#include <poll.h>
#include <signal.h>
#include <string_view>
#include <unordered_set>
#include <vector>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace {

constexpr std::size_t max_file_size = 16U * 1024U * 1024U;

std::mutex state_mutex;
std::shared_ptr<sx::privsep::files::Client> installed_client;
sx::privsep::files::Targets installed_targets;
pid_t helper_pid = -1;

int write_all(int fd, const char* data, std::size_t size) {
    std::size_t offset = 0;
    while(offset < size) {
        const auto result = ::write(fd, data + offset, size - offset);
        if(result > 0) { offset += static_cast<std::size_t>(result); continue; }
        if(result < 0 && errno == EINTR) continue;
        if(result == 0) errno = EIO;
        return -1;
    }
    return 0;
}

int read_fd(int fd, std::string& output) {
    output.clear();
    std::array<char, 16384> buffer{};
    for(;;) {
        const auto result = ::read(fd, buffer.data(), buffer.size());
        if(result > 0) {
            if(output.size() + static_cast<std::size_t>(result) > max_file_size) {
                output.clear(); errno = EFBIG; return -1;
            }
            output.append(buffer.data(), static_cast<std::size_t>(result));
            continue;
        }
        if(result == 0) return 0;
        if(errno == EINTR) continue;
        output.clear();
        return -1;
    }
}

int open_regular_readonly(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) return -1;
    struct stat state{};
    if(::fstat(fd, &state) != 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    if(!S_ISREG(state.st_mode)) {
        ::close(fd);
        errno = EINVAL;
        return -1;
    }
    return fd;
}

bool safe_version(std::string_view value) {
    if(value.empty() || value.size() > 128) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '.' || c == '_' || c == '-';
    });
}

int make_content_fd(const std::string& content) {
    if(content.size() > max_file_size) { errno = EFBIG; return -1; }
    const int fd = ::memfd_create("smithproxy-config", MFD_CLOEXEC);
    if(fd < 0) return -1;
    if(write_all(fd, content.data(), content.size()) != 0 || ::lseek(fd, 0, SEEK_SET) < 0) {
        const int saved = errno; ::close(fd); errno = saved; return -1;
    }
    return fd;
}

int copy_fd(int source, int destination) {
    if(::lseek(source, 0, SEEK_SET) < 0) return -1;
    std::array<char, 16384> buffer{};
    std::size_t total = 0;
    for(;;) {
        const auto result = ::read(source, buffer.data(), buffer.size());
        if(result > 0) {
            total += static_cast<std::size_t>(result);
            if(total > max_file_size) { errno = EFBIG; return -1; }
            if(write_all(destination, buffer.data(), static_cast<std::size_t>(result)) != 0) return -1;
            continue;
        }
        if(result == 0) return 0;
        if(errno == EINTR) continue;
        return -1;
    }
}

int atomic_replace_from_fd(const std::string& path, int source) {
    namespace fs = std::filesystem;
    const fs::path target(path);
    if(target.filename().empty() || target.parent_path().empty()) { errno = EINVAL; return -1; }
    const int directory = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if(directory < 0) return -1;

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;
    struct stat existing{};
    if(::fstatat(directory, target.filename().c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        if(!S_ISREG(existing.st_mode)) { ::close(directory); errno = EINVAL; return -1; }
        mode = existing.st_mode & 0777;
    } else if(errno != ENOENT) {
        const int saved = errno; ::close(directory); errno = saved; return -1;
    }

    static std::uint64_t sequence = 0;
    const std::string temporary = "." + target.filename().string() + ".tmp."
        + std::to_string(::getpid()) + "." + std::to_string(++sequence);
    const int output = ::openat(directory, temporary.c_str(),
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if(output < 0) { const int saved = errno; ::close(directory); errno = saved; return -1; }
    int result = copy_fd(source, output);
    if(result == 0 && ::fchmod(output, mode) != 0) result = -1;
    if(result == 0 && ::fsync(output) != 0) result = -1;
    int saved = errno;
    if(::close(output) != 0 && result == 0) { result = -1; saved = errno; }
    if(result == 0 && ::renameat(directory, temporary.c_str(), directory,
                                target.filename().c_str()) != 0) { result = -1; saved = errno; }
    if(result == 0 && ::fsync(directory) != 0) { result = -1; saved = errno; }
    if(result != 0) ::unlinkat(directory, temporary.c_str(), 0);
    ::close(directory);
    errno = saved;
    return result;
}

sx::privsep::files::Reply error_reply(int error) {
    return sx::comm::error_reply(error);
}

class PingOperation final: public sx::privsep::files::Operation {
public:
    sx::privsep::files::Reply execute(const sx::privsep::files::Request& request) override {
        if(request.fd >= 0 || !request.payload.empty()) return error_reply(EINVAL);
        return {};
    }
};

class ConfigOperation final: public sx::privsep::files::Operation {
public:
    explicit ConfigOperation(std::string target): target_(std::move(target)) {}

    sx::privsep::files::Reply execute(const sx::privsep::files::Request& request) override {
        using sx::privsep::files::Opcode;
        const auto opcode = static_cast<Opcode>(request.opcode);
        if(opcode == Opcode::ConfigRead) {
            if(request.fd >= 0 || !request.payload.empty()) return error_reply(EINVAL);
            const int fd = open_regular_readonly(target_);
            if(fd < 0) return error_reply(errno);
            return {0, {}, fd};
        }

        const bool backup = opcode == Opcode::ConfigBackup;
        if(opcode != Opcode::ConfigWrite && !backup) return error_reply(EOPNOTSUPP);
        if(request.fd < 0 || (!backup && !request.payload.empty())
           || (backup && !safe_version(request.payload))) return error_reply(EINVAL);
        const std::string destination = backup
            ? target_ + "." + request.payload + ".bak.cfg" : target_;
        if(atomic_replace_from_fd(destination, request.fd) != 0) return error_reply(errno);
        return {};
    }

private:
    std::string target_;
};

class PidOperation final: public sx::privsep::files::Operation {
public:
    explicit PidOperation(std::string target): target_(std::move(target)) {}
    ~PidOperation() override { cleanup(); }

    sx::privsep::files::Reply execute(const sx::privsep::files::Request& request) override {
        using sx::privsep::files::Opcode;
        switch(static_cast<Opcode>(request.opcode)) {
            case Opcode::PidExists: return exists(request);
            case Opcode::PidWrite: return write(request);
            case Opcode::PidRemove: return remove(request);
            default: return error_reply(EOPNOTSUPP);
        }
    }

    void shutdown() noexcept override { cleanup(); }

private:
    sx::privsep::files::Reply exists(const sx::privsep::files::Request& request) const {
        if(request.fd >= 0 || !request.payload.empty()) return error_reply(EINVAL);
        struct stat state{};
        if(::lstat(target_.c_str(), &state) == 0) return {0, std::string(1, '\1'), -1};
        if(errno == ENOENT) return {0, std::string(1, '\0'), -1};
        return error_reply(errno);
    }

    sx::privsep::files::Reply write(const sx::privsep::files::Request& request) {
        if(request.fd >= 0 || owned_) return error_reply(request.fd >= 0 ? EINVAL : EALREADY);
        long long value = 0;
        const auto parsed = std::from_chars(request.payload.data(),
                                            request.payload.data() + request.payload.size(), value);
        if(request.payload.empty() || parsed.ec != std::errc{}
           || parsed.ptr != request.payload.data() + request.payload.size()
           || value <= 1 || value > std::numeric_limits<pid_t>::max()) return error_reply(EINVAL);
        const int fd = ::open(target_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(fd < 0) return error_reply(errno);
        const int result = write_all(fd, request.payload.data(), request.payload.size());
        int saved = errno;
        struct stat created{};
        if(result == 0 && ::fstat(fd, &created) != 0) saved = errno;
        const bool valid_inode = result == 0 && S_ISREG(created.st_mode);
        if(::close(fd) != 0 && result == 0) {
            saved = errno;
            ::unlink(target_.c_str());
            return error_reply(saved);
        }
        if(result != 0 || !valid_inode) {
            ::unlink(target_.c_str());
            return error_reply(result != 0 ? saved : EIO);
        }
        owned_ = true;
        device_ = created.st_dev;
        inode_ = created.st_ino;
        return {};
    }

    sx::privsep::files::Reply remove(const sx::privsep::files::Request& request) {
        if(request.fd >= 0 || !request.payload.empty()) return error_reply(EINVAL);
        if(!owned_) return error_reply(EPERM);
        struct stat current{};
        if(::lstat(target_.c_str(), &current) != 0) {
            if(errno != ENOENT) return error_reply(errno);
        } else if(current.st_dev != device_ || current.st_ino != inode_) {
            owned_ = false;
            return error_reply(ESTALE);
        } else if(::unlink(target_.c_str()) != 0) {
            return error_reply(errno);
        }
        owned_ = false;
        return {};
    }

    void cleanup() noexcept {
        if(!owned_) return;
        struct stat current{};
        if(::lstat(target_.c_str(), &current) == 0
           && current.st_dev == device_ && current.st_ino == inode_) {
            ::unlink(target_.c_str());
        }
        owned_ = false;
    }

    std::string target_;
    bool owned_ = false;
    dev_t device_ = 0;
    ino_t inode_ = 0;
};

std::shared_ptr<sx::privsep::files::Client> current_client() {
    std::lock_guard lock(state_mutex);
    return installed_client;
}

bool target_matches(const std::string& actual, const std::string& expected) {
    return !expected.empty() && actual == expected;
}

[[noreturn]] void helper_entry(int channel, sx::privsep::files::Targets targets) {
    if(::setpgid(0, 0) != 0) ::_exit(EXIT_FAILURE);
    // EOF on the private control channel is the ownership signal.  Unlike a
    // parent-death signal it lets Server unwind and remove an owned PID file.
    sx::privsep::files::Server server(channel, std::move(targets));
    ::close(channel);
    const int result = server.run();
    ::_exit(result == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

} // namespace

namespace sx::privsep::files {

int read_file(const std::string& path, std::string& output) {
    const int fd = open_regular_readonly(path);
    if(fd < 0) return -1;
    const int result = read_fd(fd, output);
    const int saved = errno;
    ::close(fd);
    errno = saved;
    return result;
}

int write_file_atomic(const std::string& path, const std::string& content) {
    const int fd = make_content_fd(content);
    if(fd < 0) return -1;
    const int result = atomic_replace_from_fd(path, fd);
    const int saved = errno;
    ::close(fd);
    errno = saved;
    return result;
}

int write_backup_atomic(const std::string& path, const std::string& version_text,
                        const std::string& content) {
    if(!safe_version(version_text)) { errno = EINVAL; return -1; }
    return write_file_atomic(path + "." + version_text + ".bak.cfg", content);
}

Client::Client(int fd, std::chrono::milliseconds timeout): sx::comm::Client(fd, timeout) {}

int Client::ping() {
    Reply response;
    return request(static_cast<std::uint8_t>(Opcode::Ping), {}, -1, response);
}

int Client::config_read(std::string& output) {
    Reply response;
    if(request(static_cast<std::uint8_t>(Opcode::ConfigRead), {}, -1, response) != 0) return -1;
    if(response.fd < 0) { errno = EPROTO; return -1; }
    const int result = read_fd(response.fd, output);
    const int saved = errno; ::close(response.fd); response.fd = -1; errno = saved; return result;
}

int Client::config_write(const std::string& content) {
    const int fd = make_content_fd(content);
    if(fd < 0) return -1;
    Reply response;
    const int result = request(static_cast<std::uint8_t>(Opcode::ConfigWrite), {}, fd, response);
    const int saved = errno; ::close(fd); errno = saved; return result;
}

int Client::config_backup(const std::string& version_text, const std::string& content) {
    if(!safe_version(version_text)) { errno = EINVAL; return -1; }
    const int fd = make_content_fd(content);
    if(fd < 0) return -1;
    Reply response;
    const int result = request(static_cast<std::uint8_t>(Opcode::ConfigBackup), version_text, fd, response);
    const int saved = errno; ::close(fd); errno = saved; return result;
}

int Client::pid_exists(bool& output) {
    Reply response;
    if(request(static_cast<std::uint8_t>(Opcode::PidExists), {}, -1, response) != 0) return -1;
    const auto& value = response.payload;
    if(value.size() != 1 || (value[0] != 0 && value[0] != 1)) { errno = EPROTO; return -1; }
    output = value[0] != 0;
    return 0;
}

int Client::pid_write(pid_t pid) {
    Reply response;
    return request(static_cast<std::uint8_t>(Opcode::PidWrite), std::to_string(pid), -1, response);
}

int Client::pid_remove() {
    Reply response;
    return request(static_cast<std::uint8_t>(Opcode::PidRemove), {}, -1, response);
}

Server::Server(int fd, Targets targets): sx::comm::Server(fd) {
    auto ping = std::make_shared<PingOperation>();
    auto config = std::make_shared<ConfigOperation>(targets.config);
    auto pid = std::make_shared<PidOperation>(targets.pid);
    register_operation(Opcode::Ping, std::move(ping));
    register_operation(Opcode::ConfigRead, config);
    register_operation(Opcode::ConfigWrite, config);
    register_operation(Opcode::ConfigBackup, std::move(config));
    register_operation(Opcode::PidExists, pid);
    register_operation(Opcode::PidWrite, pid);
    register_operation(Opcode::PidRemove, std::move(pid));
}

int start_local_helper(Targets targets) {
    std::lock_guard lock(state_mutex);
    if(helper_pid > 0 || installed_client || targets.config.empty() || targets.pid.empty()) {
        errno = helper_pid > 0 || installed_client ? EALREADY : EINVAL;
        return -1;
    }
    int channels[2] = {-1, -1};
    if(socle::privsep::make_channel_pair(channels) != 0) return -1;
    const pid_t child = ::fork();
    if(child < 0) { const int saved = errno; ::close(channels[0]); ::close(channels[1]); errno = saved; return -1; }
    if(child == 0) { ::close(channels[0]); helper_entry(channels[1], std::move(targets)); }
    ::close(channels[1]);
    auto client = std::make_shared<Client>(channels[0]);
    ::close(channels[0]);
    if(client->ping() != 0) {
        const int saved = errno; ::kill(child, SIGTERM);
        while(::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        errno = saved; return -1;
    }
    installed_targets = std::move(targets);
    installed_client = std::move(client);
    helper_pid = child;
    return 0;
}

int stop_local_helper() {
    std::lock_guard lock(state_mutex);
    installed_client.reset();
    if(helper_pid <= 0) return 0;
    int status = 0;
    pid_t result;
    do { result = ::waitpid(helper_pid, &status, 0); } while(result < 0 && errno == EINTR);
    helper_pid = -1;
    if(result < 0 && errno == ECHILD) return 0;
    if(result < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        if(result >= 0) errno = ECHILD;
        return -1;
    }
    return 0;
}

int config_read(const std::string& path, std::string& output) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.config)) { errno = EACCES; return -1; }
        return client->config_read(output);
    }
    return read_file(path, output);
}

int config_write(const std::string& path, const std::string& content) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.config)) { errno = EACCES; return -1; }
        return client->config_write(content);
    }
    return write_file_atomic(path, content);
}

int config_backup(const std::string& path, const std::string& version_text,
                  const std::string& content) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.config)) { errno = EACCES; return -1; }
        return client->config_backup(version_text, content);
    }
    return write_backup_atomic(path, version_text, content);
}

int pid_exists(const std::string& path, bool& output) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.pid)) { errno = EACCES; return -1; }
        return client->pid_exists(output);
    }
    struct stat state{};
    if(::lstat(path.c_str(), &state) == 0) { output = true; return 0; }
    if(errno == ENOENT) { output = false; return 0; }
    return -1;
}

int pid_write(const std::string& path, pid_t pid) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.pid)) { errno = EACCES; return -1; }
        return client->pid_write(pid);
    }
    const std::string content = std::to_string(pid);
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0) return -1;
    const int result = write_all(fd, content.data(), content.size());
    const int saved = errno; ::close(fd);
    if(result != 0) ::unlink(path.c_str());
    errno = saved;
    return result;
}

int pid_remove(const std::string& path) {
    if(auto client = current_client()) {
        if(!target_matches(path, installed_targets.pid)) { errno = EACCES; return -1; }
        return client->pid_remove();
    }
    return ::unlink(path.c_str());
}

} // namespace sx::privsep::files
