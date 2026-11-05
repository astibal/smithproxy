#include "config_cli2_smithproxy.hpp"
#include "config_cli2_schema.hpp"

#include <service/cfgapi/cfgapi.hpp>
#include <service/cfgapi/cfg_numeric.hpp>
#include <service/cfgapi/cfgvalue.hpp>
#include <service/core/smithproxy.hpp>
#include <inspect/sigfactory.hpp>
#include <utils/str.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <sstream>

using namespace smithproxy::config_cli;

namespace {

namespace tx = sx::cfg::tx;

std::optional<bool> config_bool(std::string value) {
    if(value.empty()) return true;
    value = string_tolower(value);
    if(value == "true" || value == "1" || value == "yes" || value == "y" || value == "t")
        return true;
    if(value == "false" || value == "0" || value == "no" || value == "n" || value == "f")
        return false;
    return std::nullopt;
}

std::optional<tx::Value> transaction_array_value(
    libconfig::Setting const& setting,
    std::vector<std::string> const& arguments,
    std::string& error) {
    std::vector<std::string> values;
    for(auto const& argument : arguments) {
        auto items = string_split(argument, ',');
        values.insert(values.end(), items.begin(), items.end());
    }

    // Validate the complete replacement before converting any element. This
    // preserves the existing all-or-nothing behavior of CLI array writes.
    for(auto& value : values) {
        auto checked = CfgValueHelp::get().value_check(setting.getPath(), value);
        if(!checked.first) {
            error = checked.second.empty() ? "invalid array value" : checked.second;
            return std::nullopt;
        }
        value = std::move(*checked.first);
    }

    auto element_type = libconfig::Setting::TypeString;
    if(setting.getLength() > 0) {
        element_type = setting[0].getType();
    } else if(sx::cfg::integer_array_path(setting.getPath())) {
        // libconfig forgets the element type of an empty array. These schema
        // paths are the two arrays which are defined as numeric.
        element_type = libconfig::Setting::TypeInt;
    }

    switch(element_type) {
        case libconfig::Setting::TypeInt:
        case libconfig::Setting::TypeInt64: {
            std::vector<std::int64_t> converted;
            converted.reserve(values.size());
            for(auto const& value : values) {
                auto parsed = sx::cfg::parse_number<std::int64_t>(value);
                if(!parsed) { error = "array value is not an integer"; return std::nullopt; }
                converted.push_back(*parsed);
            }
            return converted;
        }
        case libconfig::Setting::TypeBoolean: {
            std::vector<bool> converted;
            converted.reserve(values.size());
            for(auto const& value : values) {
                auto parsed = config_bool(value);
                if(!parsed) { error = "array value is not boolean"; return std::nullopt; }
                converted.push_back(*parsed);
            }
            return converted;
        }
        case libconfig::Setting::TypeFloat: {
            std::vector<double> converted;
            converted.reserve(values.size());
            for(auto const& value : values) {
                auto parsed = sx::cfg::parse_number<double>(value);
                if(!parsed) { error = "array value is not numeric"; return std::nullopt; }
                converted.push_back(*parsed);
            }
            return converted;
        }
        case libconfig::Setting::TypeString:
            return values;
        case libconfig::Setting::TypeNone:
        case libconfig::Setting::TypeGroup:
        case libconfig::Setting::TypeArray:
        case libconfig::Setting::TypeList:
            error = "unsupported configuration array element type";
            return std::nullopt;
    }

    error = "unsupported configuration array element type";
    return std::nullopt;
}

std::optional<tx::Value> transaction_value(
    libconfig::Setting const& setting,
    std::vector<std::string> const& values,
    std::string& error) {
    if(setting.isArray()) return transaction_array_value(setting, values, error);

    std::string value = values.empty() ? std::string {} : values.front();
    auto checked = CfgValueHelp::get().value_check(setting.getPath(), value);
    if(!checked.first) {
        error = checked.second.empty() ? "invalid value" : checked.second;
        return std::nullopt;
    }
    value = std::move(*checked.first);

    switch(setting.getType()) {
        case libconfig::Setting::TypeInt:
        case libconfig::Setting::TypeInt64:
            if(auto parsed = sx::cfg::parse_number<std::int64_t>(value)) return *parsed;
            break;
        case libconfig::Setting::TypeBoolean:
            if(auto parsed = config_bool(value)) return *parsed;
            break;
        case libconfig::Setting::TypeFloat:
            if(auto parsed = sx::cfg::parse_number<double>(value)) return *parsed;
            break;
        case libconfig::Setting::TypeString:
            return value;
        case libconfig::Setting::TypeNone:
        case libconfig::Setting::TypeGroup:
        case libconfig::Setting::TypeList:
            error = "transactional set supports scalar and array values only";
            return std::nullopt;
        case libconfig::Setting::TypeArray:
            break;
    }

    error = "value does not match the configuration type";
    return std::nullopt;
}

bool transaction_set(
    std::string const& subscriber_id,
    libconfig::Setting const& setting,
    std::vector<std::string> const& values,
    std::string& error) {
    // CLI arguments are text. Convert them to the exact libconfig scalar type
    // before they enter the transaction layer, so Set never relies on an
    // ambiguous string conversion.
    auto value = transaction_value(setting, values, error);
    if(!value) return false;

    // Creating a Transaction captures the current revision and acquires its
    // commit lease. Until this object is destroyed or committed, no other
    // configuration writer can change that revision underneath us.
    auto transaction = CfgFactory::make_transaction(subscriber_id);
    if(!transaction) {
        error = transaction.error().detail;
        return false;
    }

    // The single-operation convenience form performs both remaining phases:
    // it prepares and validates an isolated candidate, then atomically applies
    // it to running config and records the resulting revision.
    const std::string path = setting.getPath();
    auto committed = transaction->commit(
        tx::Set {path, std::move(*value)}, "set " + path);
    if(!committed) {
        error = committed.error().detail;
        return false;
    }
    return true;
}

std::string unmask(std::string path) {
    sx::str::string_replace_all(path, ".[x]", "");
    return path;
}

bool list_index(std::string_view value, int& result) {
    if (value.size() < 3 || value.front() != '[' || value.back() != ']') return false;
    const auto parsed = std::from_chars(value.data() + 1, value.data() + value.size() - 1, result);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() - 1 && result >= 0;
}

bool is_listener_action(CfgValue::live_apply_t action) {
    return action == CfgValue::live_apply_t::tproxy ||
           action == CfgValue::live_apply_t::redirect ||
           action == CfgValue::live_apply_t::socks ||
           action == CfgValue::live_apply_t::http_connect;
}

bool is_worker_action(CfgValue::live_apply_t action) {
    return action == CfgValue::live_apply_t::workers_tproxy ||
           action == CfgValue::live_apply_t::workers_socks ||
           action == CfgValue::live_apply_t::workers_http_connect;
}

SmithProxy::LiveListener live_listener(CfgValue::live_apply_t action) {
    switch (action) {
        case CfgValue::live_apply_t::tproxy: return SmithProxy::LiveListener::tproxy;
        case CfgValue::live_apply_t::redirect: return SmithProxy::LiveListener::redirect;
        case CfgValue::live_apply_t::socks: return SmithProxy::LiveListener::socks;
        case CfgValue::live_apply_t::http_connect: return SmithProxy::LiveListener::http_connect;
        default: return SmithProxy::LiveListener::tproxy;
    }
}

SmithProxy::LiveWorkers live_workers(CfgValue::live_apply_t action) {
    switch (action) {
        case CfgValue::live_apply_t::workers_socks: return SmithProxy::LiveWorkers::socks;
        case CfgValue::live_apply_t::workers_http_connect: return SmithProxy::LiveWorkers::http_connect;
        default: return SmithProxy::LiveWorkers::tproxy;
    }
}

bool reload_section(const std::string& section) {
    using cleanup_fn = size_t (CfgFactory::*)();
    using load_fn = int (CfgFactory::*)();
    struct reload_handler {
        std::string_view section;
        cleanup_fn cleanup;
        load_fn load;
    };

    static constexpr std::array handlers {
        reload_handler{"proto_objects", &CfgFactory::cleanup_db_proto, &CfgFactory::load_db_proto},
        reload_handler{"port_objects", &CfgFactory::cleanup_db_port, &CfgFactory::load_db_port},
        reload_handler{"address_objects", &CfgFactory::cleanup_db_address, &CfgFactory::load_db_address},
        reload_handler{"detection_profiles", &CfgFactory::cleanup_db_prof_detection,
                       &CfgFactory::load_db_prof_detection},
        reload_handler{"content_profiles", &CfgFactory::cleanup_db_prof_content,
                       &CfgFactory::load_db_prof_content},
        reload_handler{"tls_ca", &CfgFactory::cleanup_db_tls_ca, &CfgFactory::load_db_tls_ca},
        reload_handler{"tls_profiles", &CfgFactory::cleanup_db_prof_tls, &CfgFactory::load_db_prof_tls},
        reload_handler{"ssh_profiles", &CfgFactory::cleanup_db_prof_ssh, &CfgFactory::load_db_prof_ssh},
        reload_handler{"alg_dns_profiles", &CfgFactory::cleanup_db_prof_alg_dns,
                       &CfgFactory::load_db_prof_alg_dns},
        reload_handler{"auth_profiles", &CfgFactory::cleanup_db_prof_auth, &CfgFactory::load_db_prof_auth},
        reload_handler{"routing", &CfgFactory::cleanup_db_routing, &CfgFactory::load_db_routing},
        reload_handler{"policy", &CfgFactory::cleanup_db_policy, &CfgFactory::load_db_policy},
    };

    auto factory = CfgFactory::get();
    const auto handler = std::find_if(handlers.begin(), handlers.end(),
                                      [&section](const auto& candidate) {
                                          return candidate.section == section;
                                      });
    if (handler != handlers.end()) {
        (factory.get()->*handler->cleanup)();
        return (factory.get()->*handler->load)() >= 0;
    }

    // Signature sections share one tree, so either edit rebuilds both groups.
    if (signature_section(section)) {
        auto& tree = SigFactory::get().signature_tree();
        tree.reset();
        tree.group_add(true);
        tree.group_add(true);
        factory->load_signatures(CfgFactory::cfg_obj(), "starttls_signatures", tree, 0);
        factory->load_signatures(CfgFactory::cfg_obj(), "detection_signatures", tree);
        return true;
    }

    // Scalar settings are already applied by cfg_write_value/apply_config_change.
    return true;
}

bool record_change(const std::string& source, std::string description, std::string& error) {
    if (!CfgFactory::get()->record_revision(source, std::move(description))) {
        error = "configuration changed, but its revision snapshot could not be created";
        return false;
    }
    return true;
}

std::string setting_text(const libconfig::Setting& parent, const char* name, std::string_view fallback) {
    if (!parent.exists(name)) return std::string(fallback);
    try {
        const auto& value = parent[name];
        if (value.isArray() || value.isList()) {
            std::ostringstream result;
            for (int i = 0; i < value.getLength(); ++i) {
                if (i) result << ',';
                result << static_cast<const char*>(value[i]);
            }
            const auto text = result.str();
            return text.empty() ? std::string(fallback) : text;
        }
        const char* text = value;
        return text ? text : std::string(fallback);
    } catch (const libconfig::SettingException&) {
        return std::string(fallback);
    }
}

std::string policy_description(const libconfig::Setting& policy, const libconfig::Setting& root) {
    std::string description = setting_text(policy, "name", "<unnamed>") + ": " +
                              setting_text(policy, "proto", "any") + " " +
                              setting_text(policy, "src", "any") + " -> " +
                              setting_text(policy, "dst", "any") + ":" +
                              setting_text(policy, "dport", "all") + ", nat: " +
                              setting_text(policy, "nat", "none");

    const auto routing_name = setting_text(policy, "routing", "none");
    if (routing_name != "none" && !routing_name.empty()) {
        description += ", routing: " + routing_name;
        try {
            if (root.exists("routing")) {
                const auto& routing = root["routing"];
                if (routing.exists(routing_name.c_str()))
                    description += ", lb: " + setting_text(routing[routing_name.c_str()],
                                                            "dnat_lb_method", "round-robin");
            }
        } catch (const libconfig::SettingException&) {
            // Keep the referenced routing name visible even when its profile is invalid.
        }
    }
    return description + " -> " + setting_text(policy, "action", "accept");
}

}  // namespace

ConfigCli2Access make_smithproxy_config_access(std::string subscriber_id) {
    ConfigCli2Access access;
    access.root = []() -> libconfig::Setting& { return CfgFactory::cfg_root(); };
    access.mutex = &CfgFactory::lock();
    access.collection_kind = collection_kind;
    access.can_add = [](std::string_view path) {
        const auto kind = collection_kind(path);
        return kind != ConfigCollectionKind::none;
    };
    access.can_move = [](std::string_view path) { return path == "policy"; };
    access.describe_entry = [](std::string_view parent_path, const libconfig::Setting& entry) {
        return parent_path == "policy" && entry.isGroup()
                   ? policy_description(entry, CfgFactory::cfg_root())
                   : std::string{};
    };
    access.values = [](std::string_view path, std::string_view property) {
        std::vector<libcli2::CompletionItem> result;
        const std::string section(path);
        std::string name(property);
        auto entry = CfgValueHelp::get().find(section + "." + name);
        if (!entry) entry = CfgValueHelp::get().find(sx::str::cli::mask_all(section + "." + name));
        if (entry)
            for (auto value : entry->get().suggestion_generate(section, name)) result.push_back({std::move(value), {}});
        return result;
    };
    access.set = [subscriber_id](std::string_view path, std::string_view property,
                                       const std::vector<std::string>& values, std::string& error) {
        auto guard = CfgFactory::write_gate()->enter(CfgFactory::lock());
        if(!guard) {
            error = "configuration is locked by an active commit lease";
            return false;
        }
        const std::string section(path);
        std::string name(property);
        auto metadata = CfgValueHelp::get().find(section + "." + name);
        const auto live_apply = metadata ? metadata->get().live_apply() : CfgValue::live_apply_t::none;
        bool previous_enabled = false;
        switch (live_apply) {
            case CfgValue::live_apply_t::tproxy: previous_enabled = CfgFactory::get()->accept_tproxy; break;
            case CfgValue::live_apply_t::redirect: previous_enabled = CfgFactory::get()->accept_redirect; break;
            case CfgValue::live_apply_t::socks: previous_enabled = CfgFactory::get()->accept_socks; break;
            case CfgValue::live_apply_t::http_connect: previous_enabled = CfgFactory::get()->accept_http_connect; break;
            case CfgValue::live_apply_t::workers_tproxy:
            case CfgValue::live_apply_t::workers_socks:
            case CfgValue::live_apply_t::workers_http_connect:
            case CfgValue::live_apply_t::none: break;
        }
        if (!CfgFactory::cfg_obj().exists(section)) { error = "unknown configuration section"; return false; }
        auto& setting = CfgFactory::cfg_obj().lookup(section);
        if (!setting.exists(name.c_str())) { error = "unknown property: " + name; return false; }
        auto& property_setting = setting[name.c_str()];
        if(live_apply == CfgValue::live_apply_t::none &&
           (property_setting.isScalar() || property_setting.isArray())) {
            return transaction_set(subscriber_id, property_setting, values, error);
        }
        std::string previous_value;
        if (is_worker_action(live_apply))
            previous_value = std::to_string(static_cast<int>(setting[name.c_str()]));
        auto [written, message] = CfgFactory::get()->cfg_write_value(setting, false, name, values);
        if (!written) { error = message.empty() ? "cannot write value" : message; return false; }
        if (!CfgFactory::get()->apply_config_change(setting.getPath()))
            error = "value stored, but live apply failed";
        // Listener operations may block for a drain, so never hold the configuration
        // mutex while waiting for their threads.
        if (is_listener_action(live_apply) &&
            !guard->while_config_unlocked([&] {
                return SmithProxy::instance().apply_listener_setting(
                    live_listener(live_apply), previous_enabled);
            })) {
            auto& rollback_setting = CfgFactory::cfg_obj().lookup(section);
            CfgFactory::get()->cfg_write_value(rollback_setting, false, name,
                                               {previous_enabled ? "true" : "false"});
            CfgFactory::get()->load_settings();
            error = "listener change failed; value rolled back";
            return false;
        }
        if (is_worker_action(live_apply)) {
            const auto workers = live_workers(live_apply);
            if (!guard->while_config_unlocked([&] {
                    return SmithProxy::instance().apply_worker_setting(workers);
                })) {
                // Restore both the stored value and the running listener topology.
                auto& rollback_setting = CfgFactory::cfg_obj().lookup(section);
                CfgFactory::get()->cfg_write_value(rollback_setting, false, name, {previous_value});
                CfgFactory::get()->load_settings();
                guard->while_config_unlocked([&] {
                    return SmithProxy::instance().apply_worker_setting(workers);
                });
                error = "worker change failed; value rolled back";
                return false;
            }
        }
        return record_change(subscriber_id,
                             "set " + section + "." + name,
                             error);
    };
    access.set_confirmation = [](std::string_view path, std::string_view property,
                                 const std::vector<std::string>& values) {
        if (values.size() != 1) return std::string{};
        auto metadata = CfgValueHelp::get().find(std::string(path) + "." + std::string(property));
        if (!metadata || metadata->get().confirm_subject().empty()) return std::string{};
        auto checked = CfgValueHelp::get().value_check(metadata->get().name(), values.front());
        if (!checked.first) return std::string{};
        const auto action = metadata->get().live_apply();
        if (is_worker_action(action))
            return "You are about to change <" + metadata->get().confirm_subject() +
                   "> worker count to " + *checked.first + ". Existing sessions will drain. You sure? [N/y] ";
        const bool enable = *checked.first == "true";
        return "You are about to " + std::string(enable ? "enable" : "disable") + " <" +
               metadata->get().confirm_subject() + "> listener. You sure? [N/y] ";
    };
    access.toggle = [set = access.set](std::string_view path, std::string_view property,
                                       const std::vector<std::string>& values, std::string& error) mutable {
        std::vector<std::string> current;
        auto toggles = values;
        try {
            const std::string property_name(property);
            const auto& setting = CfgFactory::cfg_obj().lookup(std::string(path))[property_name.c_str()];
            for (int i = 0; i < setting.getLength(); ++i) current.emplace_back(static_cast<const char*>(setting[i]));
        } catch (const libconfig::SettingException& exception) {
            error = exception.what();
            return false;
        }
        return set(path, property, CfgValueCleaner::toggle(current, toggles), error);
    };
    access.add = [subscriber_id](std::string_view path, const std::vector<std::string>& input, std::string& error) {
        auto guard = CfgFactory::write_gate()->enter(CfgFactory::lock());
        if(!guard) {
            error = "configuration is locked by an active commit lease";
            return false;
        }
        auto arguments = input;
        const std::string section = unmask(std::string(path));
        const auto kind = collection_kind(section);
        if (kind == ConfigCollectionKind::none) { error = "add is not supported for this section"; return false; }

        if (kind == ConfigCollectionKind::named_objects || section == "policy") {
            auto [prepared, note] = CfgFactory::cfg_add_prepare_params(section, arguments);
            if (!prepared) { error = note; return false; }
            auto [added, message] = CfgFactory::get()->cfg_add_entry(section, arguments.front());
            if (!added) { error = message; return false; }
            return record_change(subscriber_id,
                                 "add " + section + "." + arguments.front(),
                                 error);
        }

        if (!CfgFactory::cfg_obj().exists(section)) { error = "unknown configuration section"; return false; }
        auto& list = CfgFactory::cfg_root().lookup(section);
        if (!add_ordered_entry(list, section, arguments, error)) return false;

        const std::string reload = root_section(section);
        if (!reload_section(reload)) { error = "entry added, but live reload failed"; return false; }
        CfgFactory::get()->cleanup_db_policy();
        if (CfgFactory::get()->load_db_policy() < 0) { error = "entry added, but policy reload failed"; return false; }
        return record_change(subscriber_id,
                             "add entry to " + section,
                             error);
    };
    access.remove = [subscriber_id](std::string_view path, const std::vector<std::string>& entries, std::string& error) {
        // Acquire the lease before inspecting dependencies. The running
        // revision and its usage database then remain stable until commit.
        auto transaction = CfgFactory::make_transaction(subscriber_id);
        if(!transaction) {
            error = transaction.error().detail;
            return false;
        }
        const std::string section = unmask(std::string(path));
        const auto kind = collection_kind(section);
        if (!CfgFactory::cfg_obj().exists(section)) { error = "unknown configuration section"; return false; }
        auto& setting = CfgFactory::cfg_root().lookup(section);
        RemovePlan plan;
        const UsageLookup usage = kind == ConfigCollectionKind::named_objects
            ? UsageLookup([&](std::string_view name) {
                  auto element = CfgFactory::get()->section_element<CfgElement>(section, std::string(name));
                  return element && element->has_usage() ? element->usage_strvec() : std::vector<std::string>{};
              })
            : UsageLookup{};
        if (!plan_remove(setting, kind, entries, usage, plan, error)) return false;

        // Candidate removal repeats structural validation in isolation. The
        // plan above additionally supplies Smithproxy-specific usage checks.
        std::vector<std::string> transaction_entries;
        transaction_entries.reserve(plan.indexes_descending.size() + plan.names.size());
        for (const int index : plan.indexes_descending) {
            transaction_entries.push_back(std::to_string(index));
        }
        transaction_entries.insert(transaction_entries.end(), plan.names.begin(), plan.names.end());

        auto committed = transaction->commit(
            tx::Remove {section, std::move(transaction_entries)},
            "remove " + std::to_string(entries.size()) +
                (entries.size() == 1 ? " entry from " : " entries from ") + section);
        if(!committed) {
            error = committed.error().detail;
            return false;
        }
        return true;
    };
    access.move = [subscriber_id](std::string_view path, std::string_view source, std::string_view operation,
                                   std::string_view target, std::string& error) {
        auto transaction = CfgFactory::make_transaction(subscriber_id);
        if(!transaction) {
            error = transaction.error().detail;
            return false;
        }
        const std::string section = unmask(std::string(path));
        if (section != "policy") { error = "move is currently supported only for policy"; return false; }
        int from = -1;
        int to = -1;
        if (!list_index(source, from)) { error = "invalid source index"; return false; }
        const int count = CfgFactory::cfg_root().lookup("policy").getLength();
        if (operation == "up") to = from - 1;
        else if (operation == "down") to = from + 1;
        else if (operation == "top") to = 0;
        else if (operation == "bottom") to = count - 1;
        else if (!list_index(target, to)) { error = "invalid target index"; return false; }
        if (to < 0 || to >= count) { error = "target index is out of range"; return false; }
        const auto position = operation == "after" || operation == "down" || operation == "bottom"
                                ? tx::Position::after : tx::Position::before;
        const std::string description =
            "move policy " + std::string(source) + " " + std::string(operation) +
            (target.empty() ? std::string{} : " " + std::string(target));
        auto committed = transaction->commit(
            tx::Move {
                section,
                static_cast<std::size_t>(from),
                position,
                static_cast<std::size_t>(to),
            },
            description);
        if(!committed) {
            error = committed.error().detail;
            return false;
        }
        return true;
    };
    return access;
}
