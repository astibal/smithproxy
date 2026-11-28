#include "admin_config.hpp"

#include <service/cfgapi/cfg_serialization.hpp>
#include <utils/crypto.hpp>

#include <libconfig.h++>

#include <algorithm>
#include <set>
#include <stdexcept>
#include <sys/un.h>

namespace {

using libconfig::Setting;

// Unknown and disabled users perform the same PBKDF2 work as configured users
// so the login boundary does not reveal administrator names through timing.
const std::string& fallback_password_verifier() {
    static const std::string verifier =
        "$pbkdf2-sha256$" +
        std::to_string(sx::crypto::password_pbkdf2_iterations) +
        "$00000000000000000000000000000000$"
        "0000000000000000000000000000000000000000000000000000000000000000";
    return verifier;
}

void require_type(const Setting& setting, Setting::Type type, std::string_view description) {
    if(setting.getType() != type)
        throw std::invalid_argument(std::string(description) + " has an invalid type");
}

void require_members(const Setting& setting, const std::set<std::string>& allowed) {
    for(int index = 0; index < setting.getLength(); ++index) {
        const auto* name = setting[index].getName();
        if(!name || allowed.find(name) == allowed.end())
            throw std::invalid_argument("admin.cfg contains an unsupported setting");
    }
}

sx::admin::Administrator parse_administrator(const Setting& setting) {
    require_type(setting, Setting::TypeGroup, "administrator");
    require_members(setting, {"name", "enabled", "password_verifier"});

    std::string name;
    std::string verifier;
    bool enabled = true;
    const bool complete = setting.lookupValue("name", name) &&
        setting.lookupValue("enabled", enabled) &&
        setting.lookupValue("password_verifier", verifier);
    if(!complete) throw std::invalid_argument("administrator entry is incomplete");
    if(!sx::admin::valid_name(name))
        throw std::invalid_argument("administrator name is invalid");
    if(!sx::crypto::password_verifier_supported(verifier))
        throw std::invalid_argument("administrator password verifier is invalid");

    return {std::move(name), enabled, std::move(verifier)};
}

} // namespace

namespace sx::admin {

bool valid_name(std::string_view value) {
    return !value.empty() && value.size() <= 64U &&
        std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
            const bool ascii_digit = byte >= '0' && byte <= '9';
            const bool ascii_lowercase = byte >= 'a' && byte <= 'z';
            const bool ascii_uppercase = byte >= 'A' && byte <= 'Z';
            const bool separator = byte == '-' || byte == '_' ||
                                   byte == '.' || byte == '@';
            return ascii_digit || ascii_lowercase || ascii_uppercase || separator;
        });
}

bool Administrator::operator==(const Administrator& other) const noexcept {
    return name == other.name && enabled == other.enabled &&
           password_verifier == other.password_verifier;
}

// Parse the complete resource before exposing any administrator. This keeps a
// malformed entry from activating an otherwise partially valid configuration.
Admins Admins::parse(std::string_view content) {
    libconfig::Config parsed;
    try {
        parsed.readString(std::string(content));
    }
    catch(const libconfig::ParseException& error) {
        throw std::invalid_argument(
            "admin.cfg parse error at line " + std::to_string(error.getLine()));
    }

    const auto& root = parsed.getRoot();
    require_members(root, {"admin"});
    if(!root.exists("admin")) throw std::invalid_argument("admin.cfg has no admin section");

    const auto& admin = root["admin"];
    require_type(admin, Setting::TypeGroup, "admin section");
    require_members(admin, {"schema_version", "authentication", "administrators"});

    int schema_version = 0;
    if(!admin.lookupValue("schema_version", schema_version) ||
       schema_version != config_schema_version)
        throw std::invalid_argument("admin.cfg schema version is unsupported");
    if(!admin.exists("administrators"))
        throw std::invalid_argument("admin.cfg has no administrator list");

    Admins result;
    if(admin.exists("authentication")) {
        const auto& authentication = admin["authentication"];
        require_type(authentication, Setting::TypeGroup, "authentication section");
        require_members(authentication, {"socket_enabled", "socket_path"});

        authentication.lookupValue(
            "socket_enabled", result.authentication_.socket_enabled);
        std::string socket_path;
        if(authentication.lookupValue("socket_path", socket_path)) {
            const bool absolute = !socket_path.empty() && socket_path.front() == '/';
            const bool bounded = socket_path.size() < sizeof(sockaddr_un::sun_path);
            const bool contains_nul = socket_path.find('\0') != std::string::npos;
            if(!absolute || !bounded || contains_nul) {
                throw std::invalid_argument(
                    "admin authentication socket must use a bounded absolute path");
            }
            result.authentication_.socket_path = std::move(socket_path);
        }
    }

    const auto& entries = admin["administrators"];
    require_type(entries, Setting::TypeList, "administrator list");

    std::set<std::string> names;
    for(int index = 0; index < entries.getLength(); ++index) {
        auto administrator = parse_administrator(entries[index]);
        if(!names.emplace(administrator.name).second)
            throw std::invalid_argument("admin.cfg contains duplicate administrators");
        result.administrators_.push_back(std::move(administrator));
    }
    return result;
}

// Emit one deterministic schema-versioned document for archive persistence.
std::string Admins::serialize() const {
    libconfig::Config output;
    auto& admin = output.getRoot().add("admin", Setting::TypeGroup);
    admin.add("schema_version", Setting::TypeInt) = config_schema_version;
    auto& authentication = admin.add("authentication", Setting::TypeGroup);
    authentication.add("socket_enabled", Setting::TypeBoolean) =
        authentication_.socket_enabled;
    if(authentication_.socket_path) {
        authentication.add("socket_path", Setting::TypeString) =
            authentication_.socket_path->string();
    }
    auto& entries = admin.add("administrators", Setting::TypeList);
    for(const auto& administrator : administrators_) {
        auto& entry = entries.add(Setting::TypeGroup);
        entry.add("name", Setting::TypeString) = administrator.name;
        entry.add("enabled", Setting::TypeBoolean) = administrator.enabled;
        entry.add("password_verifier", Setting::TypeString) =
            administrator.password_verifier;
    }

    auto serialized = cfgapi_detail::serialize_config(output);
    if(!serialized) throw std::runtime_error("cannot serialize admin.cfg");
    return std::move(*serialized);
}

const std::vector<Administrator>& Admins::administrators() const noexcept {
    return administrators_;
}

const AuthenticationPolicy& Admins::authentication() const noexcept {
    return authentication_;
}

const Administrator* Admins::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        administrators_.begin(), administrators_.end(),
        [name](const Administrator& administrator) { return administrator.name == name; });
    return found == administrators_.end() ? nullptr : &*found;
}

AuthenticationStatus Admins::authenticate(
    std::string_view name, std::string_view password) const {
    // Always perform one verifier operation, including unknown and disabled
    // names, so account discovery does not gain a cheap timing distinction.
    const auto* administrator = valid_name(name) ? find(name) : nullptr;
    const bool configured = administrator != nullptr;
    const bool enabled = configured && administrator->enabled;
    const auto verifier = enabled
        ? std::string_view(administrator->password_verifier)
        : std::string_view(fallback_password_verifier());
    const bool matches = sx::crypto::password_matches(password, verifier);
    if(!configured) return AuthenticationStatus::not_configured;
    return enabled && matches
        ? AuthenticationStatus::authenticated
        : AuthenticationStatus::denied;
}

void Admins::upsert(Administrator administrator) {
    if(!valid_name(administrator.name))
        throw std::invalid_argument("administrator name is invalid");
    if(!sx::crypto::password_verifier_supported(administrator.password_verifier))
        throw std::invalid_argument("administrator password verifier is invalid");

    const auto found = std::find_if(
        administrators_.begin(), administrators_.end(),
        [&administrator](const Administrator& current) {
            return current.name == administrator.name;
        });
    if(found == administrators_.end()) administrators_.push_back(std::move(administrator));
    else *found = std::move(administrator);
}

bool Admins::remove(std::string_view name) {
    const auto found = std::find_if(
        administrators_.begin(), administrators_.end(),
        [name](const Administrator& administrator) { return administrator.name == name; });
    if(found == administrators_.end()) return false;
    administrators_.erase(found);
    return true;
}

} // namespace sx::admin
