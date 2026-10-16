#include "config_cli2_smithproxy.hpp"
#include "config_cli2_schema.hpp"

#include <service/cfgapi/cfgapi.hpp>
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
        std::unique_lock<std::recursive_mutex> lock(CfgFactory::lock());
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
        std::string previous_value;
        if (is_worker_action(live_apply))
            previous_value = std::to_string(static_cast<int>(setting[name.c_str()]));
        auto [written, message] = CfgFactory::get()->cfg_write_value(setting, false, name, values);
        if (!written) { error = message.empty() ? "cannot write value" : message; return false; }
        if (!CfgFactory::get()->apply_config_change(setting.getPath()))
            error = "value stored, but live apply failed";
        lock.unlock();
        // Listener operations may block for a drain, so never hold the configuration
        // mutex while waiting for their threads.
        if (is_listener_action(live_apply) &&
            !SmithProxy::instance().apply_listener_setting(live_listener(live_apply),
                                                            previous_enabled)) {
            lock.lock();
            auto& rollback_setting = CfgFactory::cfg_obj().lookup(section);
            CfgFactory::get()->cfg_write_value(rollback_setting, false, name,
                                               {previous_enabled ? "true" : "false"});
            CfgFactory::get()->load_settings();
            error = "listener change failed; value rolled back";
            return false;
        }
        if (is_worker_action(live_apply)) {
            const auto workers = live_workers(live_apply);
            if (!SmithProxy::instance().apply_worker_setting(workers)) {
                // Restore both the stored value and the running listener topology.
                lock.lock();
                auto& rollback_setting = CfgFactory::cfg_obj().lookup(section);
                CfgFactory::get()->cfg_write_value(rollback_setting, false, name, {previous_value});
                CfgFactory::get()->load_settings();
                lock.unlock();
                SmithProxy::instance().apply_worker_setting(workers);
                error = "worker change failed; value rolled back";
                return false;
            }
        }
        CfgFactory::board()->upgrade(subscriber_id);
        return true;
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
        auto arguments = input;
        const std::string section = unmask(std::string(path));
        const auto kind = collection_kind(section);
        if (kind == ConfigCollectionKind::none) { error = "add is not supported for this section"; return false; }

        if (kind == ConfigCollectionKind::named_objects || section == "policy") {
            auto [prepared, note] = CfgFactory::cfg_add_prepare_params(section, arguments);
            if (!prepared) { error = note; return false; }
            auto [added, message] = CfgFactory::get()->cfg_add_entry(section, arguments.front());
            if (!added) { error = message; return false; }
            CfgFactory::board()->upgrade(subscriber_id);
            return true;
        }

        std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
        if (!CfgFactory::cfg_obj().exists(section)) { error = "unknown configuration section"; return false; }
        auto& list = CfgFactory::cfg_root().lookup(section);
        if (!add_ordered_entry(list, section, arguments, error)) return false;

        const std::string reload = root_section(section);
        if (!reload_section(reload)) { error = "entry added, but live reload failed"; return false; }
        CfgFactory::get()->cleanup_db_policy();
        if (CfgFactory::get()->load_db_policy() < 0) { error = "entry added, but policy reload failed"; return false; }
        CfgFactory::board()->upgrade(subscriber_id);
        return true;
    };
    access.remove = [subscriber_id](std::string_view path, const std::vector<std::string>& entries, std::string& error) {
        const std::string section = unmask(std::string(path));
        std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
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
        // Planning validates every entry and dependency before the first mutation.
        try {
            for (const int index : plan.indexes_descending) setting.remove(index);
            for (const auto& name : plan.names) setting.remove(name.c_str());
        } catch (const libconfig::SettingException& exception) {
            error = exception.what();
            return false;
        }
        const std::string reload = root_section(section);
        if (!reload_section(reload)) { error = "entry removed, but live reload failed"; return false; }
        if (reload != "policy") {
            CfgFactory::get()->cleanup_db_policy();
            if (CfgFactory::get()->load_db_policy() < 0) {
                error = "entry removed, but policy reload failed";
                return false;
            }
        }
        CfgFactory::board()->upgrade(subscriber_id);
        return true;
    };
    access.move = [subscriber_id](std::string_view path, std::string_view source, std::string_view operation,
                                   std::string_view target, std::string& error) {
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
        const auto direction = operation == "after" || operation == "down" || operation == "bottom"
                                   ? CfgFactory::op_move::OP_MOVE_AFTER : CfgFactory::op_move::OP_MOVE_BEFORE;
        if (!CfgFactory::get()->move_policy(from, to, direction)) { error = "cannot move policy"; return false; }
        reload_section(section);
        CfgFactory::board()->upgrade(subscriber_id);
        return true;
    };
    return access;
}
