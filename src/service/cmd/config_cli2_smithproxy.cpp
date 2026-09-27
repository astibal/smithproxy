#include "config_cli2_smithproxy.hpp"
#include "config_cli2_schema.hpp"

#include <service/cfgapi/cfgapi.hpp>
#include <service/cfgapi/cfgvalue.hpp>
#include <inspect/sigfactory.hpp>
#include <utils/str.hpp>

#include <algorithm>
#include <charconv>

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

bool reload_section(const std::string& section) {
    auto f = CfgFactory::get();
    if (section == "proto_objects") { f->cleanup_db_proto(); return f->load_db_proto() >= 0; }
    if (section == "port_objects") { f->cleanup_db_port(); return f->load_db_port() >= 0; }
    if (section == "address_objects") { f->cleanup_db_address(); return f->load_db_address() >= 0; }
    if (section == "detection_profiles") { f->cleanup_db_prof_detection(); return f->load_db_prof_detection() >= 0; }
    if (section == "content_profiles") { f->cleanup_db_prof_content(); return f->load_db_prof_content() >= 0; }
    if (section == "tls_ca") { f->cleanup_db_tls_ca(); return f->load_db_tls_ca() >= 0; }
    if (section == "tls_profiles") { f->cleanup_db_prof_tls(); return f->load_db_prof_tls() >= 0; }
    if (section == "alg_dns_profiles") { f->cleanup_db_prof_alg_dns(); return f->load_db_prof_alg_dns() >= 0; }
    if (section == "auth_profiles") { f->cleanup_db_prof_auth(); return f->load_db_prof_auth() >= 0; }
    if (section == "routing") { f->cleanup_db_routing(); return f->load_db_routing() >= 0; }
    if (section == "policy") { f->cleanup_db_policy(); return f->load_db_policy() >= 0; }
    if (signature_section(section)) {
        auto& tree = SigFactory::get().signature_tree();
        tree.reset();
        tree.group_add(true);
        tree.group_add(true);
        f->load_signatures(CfgFactory::cfg_obj(), "starttls_signatures", tree, 0);
        f->load_signatures(CfgFactory::cfg_obj(), "detection_signatures", tree);
        return true;
    }
    return true;
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
        std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
        const std::string section(path);
        std::string name(property);
        if (!CfgFactory::cfg_obj().exists(section)) { error = "unknown configuration section"; return false; }
        auto& setting = CfgFactory::cfg_obj().lookup(section);
        if (!setting.exists(name.c_str())) { error = "unknown property: " + name; return false; }
        auto [written, message] = CfgFactory::get()->cfg_write_value(setting, false, name, values);
        if (!written) { error = message.empty() ? "cannot write value" : message; return false; }
        if (!CfgFactory::get()->apply_config_change(setting.getPath()))
            error = "value stored, but live apply failed";
        CfgFactory::board()->upgrade(subscriber_id);
        return true;
    };
    access.toggle = [set = access.set](std::string_view path, std::string_view property,
                                       const std::vector<std::string>& values, std::string& error) mutable {
        std::vector<std::string> current;
        auto toggles = values;
        try {
            const auto& setting = CfgFactory::cfg_obj().lookup(std::string(path))[std::string(property)];
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
            for (const auto& name : plan.names) setting.remove(name);
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
