#include "runtime_credentials.hpp"

#include <utils/crypto.hpp>

#include <libconfig.h++>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <stdexcept>
#include <system_error>

namespace {

constexpr std::size_t minimum_size = 32U;
constexpr std::size_t maximum_size = 256U;
constexpr std::string_view default_api_current = "/run/smithproxy/gui-api.key";
constexpr std::string_view default_api_previous = "/run/smithproxy/gui-api.previous.key";
constexpr std::string_view default_gateway_current = "/run/smithproxy/gui-gateway.key";
constexpr std::string_view default_gateway_previous = "/run/smithproxy/gui-gateway.previous.key";

bool safe_byte(const unsigned char byte) {
    return byte >= 0x20U && byte != 0x7fU;
}

std::chrono::system_clock::time_point modified_time(const struct stat& metadata) {
    return std::chrono::system_clock::from_time_t(metadata.st_mtime);
}

} // namespace

namespace sx::auth {

GuiRuntimeCredentialPolicy default_gui_runtime_credentials() {
    GuiRuntimeCredentialPolicy policy;
    policy.management_api.enabled = true;
    policy.management_api.current_path = default_api_current;
    policy.management_api.previous_path = default_api_previous;
    policy.gateway.enabled = false;
    policy.gateway.current_path = default_gateway_current;
    policy.gateway.previous_path = default_gateway_previous;
    return policy;
}

GuiRuntimeCredentialPolicy parse_gui_runtime_credentials(const std::string_view source) {
    auto policy = default_gui_runtime_credentials();
    if(source.empty()) return policy;

    libconfig::Config document;
    document.readString(std::string(source));
    const auto& root = document.getRoot();
    if(!root.exists("gui") || root["gui"].getType() != libconfig::Setting::TypeGroup)
        throw std::invalid_argument("gui.cfg has no gui group");
    const auto& gui = root["gui"];

    const auto parse_seconds = [](const libconfig::Setting& group, const char* name,
                                  std::chrono::seconds& destination) {
        long long value = destination.count();
        if(group.lookupValue(name, value)) {
            if(value <= 0 || value > 31536000LL)
                throw std::invalid_argument(std::string(name) + " is outside 1..31536000");
            destination = std::chrono::seconds(value);
        }
    };
    const auto parse_group = [&parse_seconds](
        const libconfig::Setting& group, RuntimeCredentialSpec& spec,
        const char* current_name, const char* previous_name) {
        group.lookupValue("credential_enabled", spec.enabled);
        std::string path;
        if(group.lookupValue(current_name, path)) spec.current_path = std::move(path);
        if(group.lookupValue(previous_name, path)) spec.previous_path = std::move(path);
        parse_seconds(group, "credential_bootstrap_freshness_seconds", spec.bootstrap_freshness);
        parse_seconds(group, "credential_rotation_seconds", spec.rotation_interval);
        parse_seconds(group, "credential_overlap_seconds", spec.overlap);
    };

    if(gui.exists("smithproxy")) {
        const auto& smithproxy = gui["smithproxy"];
        if(smithproxy.getType() != libconfig::Setting::TypeGroup)
            throw std::invalid_argument("gui.smithproxy is not a group");
        parse_group(smithproxy, policy.management_api,
                    "api_token_file", "previous_api_token_file");
        smithproxy.lookupValue(
            "administrator_auth_socket_enabled",
            policy.administrator_auth_socket_enabled);
        std::string administrator_auth_socket;
        if(smithproxy.lookupValue(
               "administrator_auth_socket", administrator_auth_socket)) {
            policy.administrator_auth_socket = std::move(administrator_auth_socket);
        }
    }
    if(gui.exists("gateway")) {
        const auto& gateway = gui["gateway"];
        if(gateway.getType() != libconfig::Setting::TypeGroup)
            throw std::invalid_argument("gui.gateway is not a group");
        policy.gateway.enabled = true;
        parse_group(gateway, policy.gateway, "secret_file", "previous_secret_file");
    }
    return policy;
}

RuntimeCredentialPair::RuntimeCredentialPair(
    RuntimeCredentialSpec spec, Publish publish, Log log)
    : spec_(std::move(spec)), publish_(std::move(publish)), log_(std::move(log)) {}

RuntimeCredentialPair::~RuntimeCredentialPair() { stop(); }

void RuntimeCredentialPair::report(const bool warning, std::string message) const {
    if(log_) log_(warning, message);
}

bool RuntimeCredentialPair::ensure_directory() const {
    std::error_code error;
    const auto parent = spec_.current_path.parent_path();
    if(parent.empty() || parent != spec_.previous_path.parent_path()) return false;
    std::filesystem::create_directories(parent, error);
    if(error) return false;
    const int result = ::chmod(parent.c_str(), 0750);
    return result == 0;
}

std::optional<RuntimeCredentialPair::LoadedCredential> RuntimeCredentialPair::load(
    const std::filesystem::path& path,
    const std::chrono::system_clock::time_point now,
    const bool report_missing) const {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(descriptor < 0) {
        if(report_missing || errno != ENOENT)
            report(true, "runtime credential is not readable");
        return std::nullopt;
    }

    struct stat metadata {};
    const bool metadata_ok = ::fstat(descriptor, &metadata) == 0;
    const bool trusted_owner = metadata_ok && metadata.st_uid == ::geteuid();
    const bool safe_mode = metadata_ok && (metadata.st_mode & 0027) == 0;
    const bool safe_size = metadata_ok && metadata.st_size >= static_cast<off_t>(minimum_size) &&
        metadata.st_size <= static_cast<off_t>(maximum_size + 2U);
    if(!metadata_ok || !S_ISREG(metadata.st_mode) || !trusted_owner || !safe_mode || !safe_size) {
        ::close(descriptor);
        report(true, "runtime credential has unsafe ownership, mode, or size");
        return std::nullopt;
    }

    std::string value(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0U;
    while(offset < value.size()) {
        const auto count = ::read(descriptor, value.data() + offset, value.size() - offset);
        const bool interrupted = count < 0 && errno == EINTR;
        if(interrupted) continue;
        if(count <= 0) {
            ::close(descriptor);
            report(true, "runtime credential could not be read completely");
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(count);
    }
    ::close(descriptor);
    while(!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    const bool valid = value.size() >= minimum_size && value.size() <= maximum_size &&
        std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
            return safe_byte(byte);
        });
    if(!valid) {
        report(true, "runtime credential contains invalid data");
        return std::nullopt;
    }
    const auto modified = modified_time(metadata);
    if(modified > now + std::chrono::minutes(1)) {
        report(true, "runtime credential has an invalid future modification time");
        return std::nullopt;
    }
    return LoadedCredential{std::move(value), modified};
}

bool RuntimeCredentialPair::publish_file(
    const std::filesystem::path& path, const std::string_view value) const {
    if(!ensure_directory()) return false;
    const auto nonce = sx::crypto::random_hex(8U);
    if(!nonce) return false;
    auto temporary = path;
    temporary += ".new." + std::to_string(::getpid()) + "." + *nonce;
    const int descriptor = ::open(
        temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0640);
    if(descriptor < 0) return false;

    bool written = true;
    std::size_t offset = 0U;
    while(offset < value.size()) {
        const auto count = ::write(descriptor, value.data() + offset, value.size() - offset);
        const bool interrupted = count < 0 && errno == EINTR;
        if(interrupted) continue;
        if(count <= 0) {
            written = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    const bool durable = written && ::fsync(descriptor) == 0;
    ::close(descriptor);
    if(!durable || ::rename(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        return false;
    }
    const int directory = ::open(
        path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if(directory < 0) return false;
    const bool directory_durable = ::fsync(directory) == 0;
    ::close(directory);
    return directory_durable;
}

bool RuntimeCredentialPair::remove_file(const std::filesystem::path& path) const {
    if(::unlink(path.c_str()) != 0 && errno != ENOENT) return false;
    return true;
}

bool RuntimeCredentialPair::reconcile(const std::chrono::system_clock::time_point now) {
    const bool valid_paths = !spec_.current_path.empty() && !spec_.previous_path.empty() &&
        spec_.current_path.is_absolute() && spec_.previous_path.is_absolute() &&
        spec_.current_path != spec_.previous_path &&
        spec_.current_path.parent_path() == spec_.previous_path.parent_path();
    if(!valid_paths) {
        report(true, "runtime credential paths are invalid");
        publish_({});
        return false;
    }
    if(!spec_.enabled) {
        const bool current_removed = remove_file(spec_.current_path);
        const bool previous_removed = remove_file(spec_.previous_path);
        publish_({});
        if(!current_removed || !previous_removed)
            report(true, "disabled runtime credential files could not be removed");
        return current_removed && previous_removed;
    }
    if(spec_.bootstrap_freshness.count() <= 0 || spec_.rotation_interval.count() <= 0 ||
       spec_.overlap.count() <= 0 || !ensure_directory()) {
        report(true, "runtime credential policy is invalid");
        publish_({});
        return false;
    }

    auto current = load(spec_.current_path, now, false);
    const bool runtime_file_replaced = boot_reconciled_ && active_current_ &&
        (!current || current->value != *active_current_);
    if(runtime_file_replaced) {
        if(!publish_file(spec_.current_path, *active_current_)) {
            report(true, "Core-owned runtime credential could not be restored");
            publish_({*active_current_, std::nullopt});
            return false;
        }
        current = load(spec_.current_path, now, true);
        report(true, "external runtime credential replacement was ignored");
    }
    if(!current) {
        auto generated = sx::crypto::random_hex(32U);
        if(!generated || !publish_file(spec_.current_path, *generated)) {
            report(true, "runtime credential could not be initialized");
            publish_({});
            return false;
        }
        current = load(spec_.current_path, now, true);
    }
    if(!current) {
        publish_({});
        return false;
    }

    const auto effective_modified = boot_reconciled_ && active_modified_
        ? *active_modified_
        : current->modified;
    const auto current_age = now - effective_modified;
    const bool stale_boot_seed = !boot_reconciled_ &&
        current_age > spec_.bootstrap_freshness;
    const bool scheduled_rotation = boot_reconciled_ &&
        current_age >= spec_.rotation_interval;
    if(stale_boot_seed || scheduled_rotation) {
        auto generated = sx::crypto::random_hex(32U);
        // A moderately old value may belong to a GUI that survived a Core
        // restart. Preserve it for one bounded overlap. Material older than a
        // complete rotation generation is not accepted again.
        const bool old_value_recoverable = current_age <=
            spec_.rotation_interval + spec_.overlap;
        const bool previous_written = old_value_recoverable
            ? publish_file(spec_.previous_path, current->value)
            : remove_file(spec_.previous_path);
        const bool current_written = generated && publish_file(spec_.current_path, *generated);
        if(!previous_written || !current_written) {
            report(true, "runtime credential rotation could not be published");
            publish_({current->value, std::nullopt});
            return false;
        }
        current = load(spec_.current_path, now, true);
        report(false, stale_boot_seed
            ? "stale boot credential replaced" : "runtime credential rotated");
    }

    auto previous = load(spec_.previous_path, now, false);
    if(previous && now - previous->modified > spec_.overlap) {
        if(!remove_file(spec_.previous_path))
            report(true, "expired previous runtime credential could not be removed");
        previous.reset();
    }
    if(previous && current && previous->value == current->value) {
        remove_file(spec_.previous_path);
        previous.reset();
    }
    publish_({current ? std::optional<std::string>{current->value} : std::nullopt,
              previous ? std::optional<std::string>{previous->value} : std::nullopt});
    if(current) {
        active_current_ = current->value;
        if(!active_modified_ || !runtime_file_replaced || stale_boot_seed || scheduled_rotation)
            active_modified_ = current->modified;
    }
    boot_reconciled_ = true;
    return current.has_value();
}

void RuntimeCredentialPair::start(const std::chrono::seconds poll_interval) {
    if(worker_.joinable() || poll_interval.count() <= 0) return;
    stopping_.store(false);
    worker_ = std::thread([this, poll_interval] {
        while(!stopping_.load()) {
            reconcile();
            auto lock = std::unique_lock(wakeup_mutex_);
            wakeup_.wait_for(lock, poll_interval, [this] { return stopping_.load(); });
        }
    });
}

void RuntimeCredentialPair::stop() {
    if(!worker_.joinable()) return;
    stopping_.store(true);
    wakeup_.notify_all();
    worker_.join();
}

} // namespace sx::auth
