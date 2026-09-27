#include "config_cli2_schema.hpp"

#include <set>
#include <algorithm>
#include <charconv>

namespace smithproxy::config_cli {

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

namespace {
bool ends_with(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}
}  // namespace

bool signature_section(std::string_view path) {
    return path == "starttls_signatures" || path == "detection_signatures";
}

bool content_rules_section(std::string_view path) {
    return starts_with(path, "content_profiles.") && ends_with(path, ".content_rules");
}

bool signature_flow_section(std::string_view path) {
    return (starts_with(path, "starttls_signatures.") || starts_with(path, "detection_signatures.")) &&
           ends_with(path, ".flow");
}

std::string root_section(std::string_view path) {
    return std::string(path.substr(0, path.find('.')));
}

ConfigCollectionKind collection_kind(std::string_view path) {
    static const std::set<std::string, std::less<>> named = {
        "proto_objects", "port_objects", "address_objects", "detection_profiles", "content_profiles",
        "tls_ca", "tls_profiles", "alg_dns_profiles", "auth_profiles", "routing",
    };
    if (path == "policy" || signature_section(path) || content_rules_section(path) || signature_flow_section(path))
        return ConfigCollectionKind::ordered_objects;
    if (named.find(path) != named.end()) return ConfigCollectionKind::named_objects;
    return ConfigCollectionKind::none;
}

bool add_ordered_entry(libconfig::Setting& list, std::string_view path,
                       const std::vector<std::string>& arguments, std::string& error) {
    if (!list.isList()) { error = "configuration section is not an ordered list"; return false; }
    const bool named_signature = signature_section(path);
    if (named_signature && arguments.size() != 1) {
        error = "signature requires exactly one name";
        return false;
    }
    if (!named_signature && !arguments.empty()) {
        error = "this ordered list does not accept an entry name";
        return false;
    }
    if (named_signature) {
        if (arguments.front().empty() || starts_with(arguments.front(), "__")) {
            error = "signature name must be non-empty and must not start with reserved __";
            return false;
        }
        for (int i = 0; i < list.getLength(); ++i) {
            std::string existing;
            if (list[i].lookupValue("name", existing) && existing == arguments.front()) {
                error = "signature already exists: " + arguments.front();
                return false;
            }
        }
    }

    const int old_length = list.getLength();
    try {
        auto& item = list.add(libconfig::Setting::TypeGroup);
        if (named_signature) {
            item.add("name", libconfig::Setting::TypeString) = arguments.front();
            item.add("cat", libconfig::Setting::TypeString) = "custom";
            item.add("side", libconfig::Setting::TypeString) = "client";
            if (path == "detection_signatures") item.add("group", libconfig::Setting::TypeString) = "base";
            item.add("flow", libconfig::Setting::TypeList);
        } else if (content_rules_section(path)) {
            item.add("match", libconfig::Setting::TypeString) = "a^";
            item.add("replace", libconfig::Setting::TypeString) = "";
        } else if (signature_flow_section(path)) {
            item.add("side", libconfig::Setting::TypeString) = "r";
            item.add("type", libconfig::Setting::TypeString) = "regex";
            item.add("signature", libconfig::Setting::TypeString) = "a^";
            item.add("bytes_start", libconfig::Setting::TypeInt) = 0;
            item.add("bytes_max", libconfig::Setting::TypeInt) = 1;
        } else {
            list.remove(old_length);
            error = "no ordered entry template for this section";
            return false;
        }
    } catch (const libconfig::SettingException& exception) {
        if (list.getLength() > old_length) list.remove(list.getLength() - 1);
        error = exception.what();
        return false;
    }
    return true;
}

bool plan_remove(const libconfig::Setting& collection, ConfigCollectionKind kind,
                 const std::vector<std::string>& entries, const UsageLookup& usage,
                 RemovePlan& plan, std::string& error) {
    plan = {};
    if (kind == ConfigCollectionKind::none) { error = "remove is not supported for this section"; return false; }
    if (entries.empty()) { error = "missing entry to remove"; return false; }
    for (const auto& entry : entries) {
        int index = -1;
        bool is_index = false;
        if (entry.size() >= 3 && entry.front() == '[' && entry.back() == ']') {
            const auto parsed = std::from_chars(entry.data() + 1, entry.data() + entry.size() - 1, index);
            is_index = parsed.ec == std::errc{} && parsed.ptr == entry.data() + entry.size() - 1 && index >= 0;
        }
        if (kind == ConfigCollectionKind::ordered_objects && !is_index) {
            error = "ordered section requires an index such as [0]";
            return false;
        }
        if (kind == ConfigCollectionKind::named_objects && is_index) {
            error = "named section requires an object name";
            return false;
        }
        if (is_index) plan.indexes_descending.push_back(index);
        else plan.names.push_back(entry);
    }
    std::sort(plan.indexes_descending.begin(), plan.indexes_descending.end());
    if (std::adjacent_find(plan.indexes_descending.begin(), plan.indexes_descending.end()) !=
        plan.indexes_descending.end()) {
        error = "duplicate entry index";
        return false;
    }
    std::sort(plan.names.begin(), plan.names.end());
    if (std::adjacent_find(plan.names.begin(), plan.names.end()) != plan.names.end()) {
        error = "duplicate object name";
        return false;
    }
    for (const int index : plan.indexes_descending) {
        if (index >= collection.getLength()) {
            error = "entry index is out of range: [" + std::to_string(index) + "]";
            return false;
        }
    }
    for (const auto& name : plan.names) {
        if (!collection.exists(name.c_str())) { error = "unknown object: " + name; return false; }
        const auto dependencies = usage ? usage(name) : std::vector<std::string>{};
        if (!dependencies.empty()) {
            error = "cannot remove " + name + "; used by: ";
            for (std::size_t i = 0; i < dependencies.size(); ++i) {
                if (i) error += ", ";
                error += dependencies[i];
            }
            return false;
        }
    }
    std::sort(plan.indexes_descending.rbegin(), plan.indexes_descending.rend());
    return true;
}

}  // namespace smithproxy::config_cli
