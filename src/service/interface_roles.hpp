#pragma once

#include <service/network_context.hpp>

#include <arpa/inet.h>
#include <charconv>
#include <libconfig.h++>
#include <stdexcept>

namespace sx::net {
namespace detail {

inline void parse_interface_address(const std::string& value, InterfaceRoleRule& rule) {
    const auto slash = value.find('/');
    const auto address = value.substr(0, slash);

    int maximum_prefix;
    if(::inet_pton(AF_INET, address.c_str(), rule.network.data()) == 1) {
        rule.family = AF_INET;
        maximum_prefix = 32;
    }
    else if(::inet_pton(AF_INET6, address.c_str(), rule.network.data()) == 1) {
        rule.family = AF_INET6;
        maximum_prefix = 128;
    }
    else {
        throw std::invalid_argument("invalid if_address IP");
    }

    rule.prefix = maximum_prefix;
    if(slash != std::string::npos) {
        const auto* begin = value.data() + slash + 1;
        const auto* end = value.data() + value.size();
        const auto parsed = std::from_chars(begin, end, rule.prefix);
        if(parsed.ec != std::errc{} || parsed.ptr != end ||
           rule.prefix < 0 || rule.prefix > maximum_prefix) {
            throw std::invalid_argument("invalid if_address prefix");
        }
    }

    rule.if_address = value;
}

inline void parse_interface_selectors(const libconfig::Setting& match, InterfaceRoleRule& rule) {
    if(match.getLength() == 0) {
        throw std::invalid_argument("interface match cannot be empty");
    }

    for(int i = 0; i < match.getLength(); ++i) {
        const auto& field = match[i];
        const std::string name = field.getName();
        if(field.getType() != libconfig::Setting::TypeString) {
            throw std::invalid_argument("interface selector must be a string");
        }

        const std::string value = static_cast<const char*>(field);
        if(value.empty()) {
            throw std::invalid_argument("interface selector cannot be empty");
        }

        if(name == "if_name") {
            rule.if_name = value;
        }
        else if(name == "if_address") {
            parse_interface_address(value, rule);
        }
        else {
            throw std::invalid_argument("unknown interface selector: " + name);
        }
    }
}

inline InterfaceRoleRule parse_interface_role(const libconfig::Setting& item) {
    using Setting = libconfig::Setting;
    if(item.getType() != Setting::TypeGroup ||
       !item.exists("match") || !item.exists("role") ||
       item["match"].getType() != Setting::TypeGroup ||
       item["role"].getType() != Setting::TypeString) {
        throw std::invalid_argument("interface rule requires match group and role string");
    }

    for(int i = 0; i < item.getLength(); ++i) {
        const std::string name = item[i].getName();
        if(name != "match" && name != "role") {
            throw std::invalid_argument("unknown interface rule field: " + name);
        }
    }

    InterfaceRoleRule rule;
    rule.role = static_cast<const char*>(item["role"]);
    if(rule.role.empty()) {
        throw std::invalid_argument("interface role cannot be empty");
    }

    parse_interface_selectors(item["match"], rule);
    return rule;
}

} // namespace detail

// Pure candidate parsing: no singleton access, sockets, or runtime mutations.
inline std::vector<InterfaceRoleRule> parse_interface_roles(const libconfig::Setting& settings) {
    if(!settings.exists("interfaces")) {
        return {};
    }

    const auto& list = settings["interfaces"];
    if(list.getType() != libconfig::Setting::TypeList) {
        throw std::invalid_argument("settings.interfaces must be an ordered list");
    }

    std::vector<InterfaceRoleRule> rules;
    rules.reserve(list.getLength());
    for(int i = 0; i < list.getLength(); ++i) {
        rules.push_back(detail::parse_interface_role(list[i]));
    }
    return rules;
}

inline void save_interface_roles(libconfig::Setting& settings, const std::vector<InterfaceRoleRule>& rules) {
    using Setting = libconfig::Setting;
    auto& list = settings.add("interfaces", Setting::TypeList);
    for(const auto& rule : rules) {
        auto& item = list.add(Setting::TypeGroup);
        auto& match = item.add("match", Setting::TypeGroup);
        if(!rule.if_name.empty()) {
            match.add("if_name", Setting::TypeString) = rule.if_name;
        }
        if(!rule.if_address.empty()) {
            match.add("if_address", Setting::TypeString) = rule.if_address;
        }
        item.add("role", Setting::TypeString) = rule.role;
    }
}

} // namespace sx::net
