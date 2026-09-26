#include "config_cli2.hpp"

#include <algorithm>
#include <cstdlib>

namespace {

ConfigCli2Session& session(libcli2::Context& context) {
    return *static_cast<ConfigCli2Session*>(context.user_data);
}

const ConfigCli2Session& session(const libcli2::Context& context) {
    return *static_cast<const ConfigCli2Session*>(context.user_data);
}

bool parse_index(std::string_view text, int& result) {
    if (text.size() < 3 || text.front() != '[' || text.back() != ']') return false;
    const std::string number(text.substr(1, text.size() - 2));
    char* end = nullptr;
    const long value = std::strtol(number.c_str(), &end, 10);
    if (!end || *end != '\0' || value < 0) return false;
    result = static_cast<int>(value);
    return true;
}

}  // namespace

ConfigCli2Session::ConfigCli2Session(ConfigCli2Access access) : access_(std::move(access)) {}

std::string ConfigCli2Session::path() const {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    const auto* setting = current();
    return setting && !setting->isRoot() ? setting->getPath() : std::string{};
}

bool ConfigCli2Session::enter_path(const std::vector<std::string>& components) {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    auto* target = resolve(components);
    if (!target || !navigable(*target)) return false;
    locations_.push_back(target->isRoot() ? std::string{} : target->getPath());
    return true;
}

std::vector<libcli2::CompletionItem>
ConfigCli2Session::children_at(const std::vector<std::string>& components) const {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    const auto* node = resolve(components);
    return node ? children(*node) : std::vector<libcli2::CompletionItem>{};
}

std::vector<libcli2::CompletionItem> ConfigCli2Session::current_children() const {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    const auto* node = current();
    return node ? children(*node) : std::vector<libcli2::CompletionItem>{};
}

libconfig::Setting* ConfigCli2Session::current() const {
    if (!access_.root) return nullptr;
    auto* setting = &access_.root();
    if (locations_.empty() || locations_.back().empty()) return setting;
    try {
        return &setting->lookup(locations_.back());
    } catch (const libconfig::SettingNotFoundException&) {
        return nullptr;
    }
}

libconfig::Setting* ConfigCli2Session::resolve(const std::vector<std::string>& components) const {
    auto* setting = current();
    if (!setting) return nullptr;
    try {
        for (const auto& component : components) {
            int index = -1;
            if (parse_index(component, index)) {
                if (!setting->isAggregate() || index >= setting->getLength()) return nullptr;
                setting = &(*setting)[index];
            } else {
                if (!setting->isAggregate() || !setting->exists(component.c_str())) return nullptr;
                setting = &(*setting)[component.c_str()];
            }
        }
    } catch (const libconfig::SettingException&) {
        return nullptr;
    }
    return setting;
}

std::vector<libcli2::CompletionItem> ConfigCli2Session::children(const libconfig::Setting& setting) const {
    std::vector<libcli2::CompletionItem> result;
    if (!setting.isAggregate()) return result;
    for (int i = 0; i < setting.getLength(); ++i) {
        const auto& child = setting[i];
        if (!navigable(child)) continue;
        std::string description = child.getPath();
        const char* child_name = child.getName();
        if (!child_name && child.isGroup() && child.exists("name")) {
            try {
                const char* display_name = child["name"];
                if (display_name && *display_name) description = display_name;
            } catch (const libconfig::SettingTypeException&) {
            }
        }
        result.push_back({child_name ? child_name : "[" + std::to_string(i) + "]", std::move(description)});
    }
    return result;
}

bool ConfigCli2Session::navigable(const libconfig::Setting& setting) const {
    if (setting.isGroup()) return true;
    if (!setting.isList()) return false;  // Arrays are scalar value collections.
    if (setting.getLength() > 0) return setting[0].isAggregate();
    return access_.collection_kind &&
           access_.collection_kind(setting.getPath()) != ConfigCollectionKind::none;
}

std::vector<libcli2::CompletionItem> ConfigCli2Session::properties() const {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    std::vector<libcli2::CompletionItem> result;
    const auto* setting = current();
    if (!setting || !setting->isAggregate()) return result;
    for (int i = 0; i < setting->getLength(); ++i) {
        const auto& child = (*setting)[i];
        if (child.isAggregate() && !child.isArray() && !child.isList()) continue;
        result.push_back({child.getName() ? child.getName() : "[" + std::to_string(i) + "]", {}});
    }
    return result;
}

std::vector<libcli2::CompletionItem> ConfigCli2Session::toggle_properties() const {
    std::unique_lock<std::recursive_mutex> lock;
    if (access_.mutex) lock = std::unique_lock<std::recursive_mutex>(*access_.mutex);
    std::vector<libcli2::CompletionItem> result;
    const auto* setting = current();
    if (!setting || !setting->isAggregate()) return result;
    for (int i = 0; i < setting->getLength(); ++i) {
        const auto& child = (*setting)[i];
        if ((child.isArray() || child.isList()) && child.getName()) result.push_back({child.getName(), {}});
    }
    return result;
}

void ConfigCli2Session::register_commands(libcli2::Cli& cli) {
    cli.command("configure terminal")
        .help("Enter configuration mode")
        .available_if([](const libcli2::Context& context) { return !session(context).active(); })
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            auto& state = session(context);
            state.active_ = true;
            context.mode = "config";
            state.locations_.clear();
            state.locations_.push_back({});
            if (state.access_.enter) state.access_.enter();
            return 0;
        });

    cli.command("edit")
        .help("Enter a configuration section")
        .available_if([](const libcli2::Context& context) { return session(context).active(); })
        .argument({"path", "Section name or list index", true, true, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       return state.children_at(request.arguments);
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            if (!state.enter_path(call.arguments)) {
                context.print("unknown configuration section");
                return -1;
            }
            return 0;
        });

    cli.command("set")
        .help("Set a property in the current section")
        .available_if([](const libcli2::Context& context) { return session(context).active(); })
        .argument({"property", "Property name", true, false, {}, {},
                   [](const libcli2::CompletionRequest& request) { return session(request.context).properties(); }})
        .argument({"value", "New value", true, true, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       if (!state.access_.values || request.arguments.empty())
                           return std::vector<libcli2::CompletionItem>{};
                       return state.access_.values(state.path(), request.arguments.front());
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            if (!state.access_.set || call.arguments.size() < 2) return -1;
            std::vector<std::string> values(call.arguments.begin() + 1, call.arguments.end());
            std::string error;
            if (!state.access_.set(state.path(), call.arguments.front(), values, error)) {
                context.print(error.empty() ? "cannot set value" : error);
                return -1;
            }
            return 0;
        });

    cli.command("toggle")
        .help("Toggle values in a list property")
        .available_if([](const libcli2::Context& context) { return session(context).active(); })
        .argument({"property", "List property name", true, false, {}, {},
                   [](const libcli2::CompletionRequest& request) { return session(request.context).toggle_properties(); }})
        .argument({"value", "Value to add or remove", true, true, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       if (!state.access_.values || request.arguments.empty())
                           return std::vector<libcli2::CompletionItem>{};
                       return state.access_.values(state.path(), request.arguments.front());
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            if (!state.access_.toggle || call.arguments.size() < 2) return -1;
            std::vector<std::string> values(call.arguments.begin() + 1, call.arguments.end());
            std::string error;
            if (!state.access_.toggle(state.path(), call.arguments.front(), values, error)) {
                context.print(error.empty() ? "cannot toggle value" : error);
                return -1;
            }
            return 0;
        });

    cli.command("add")
        .help("Create a new entry from the section template")
        .available_if([](const libcli2::Context& context) {
            const auto& state = session(context);
            return state.active() && static_cast<bool>(state.access_.add) && state.access_.can_add &&
                   state.access_.can_add(state.path());
        })
        .argument({"arguments", "Optional entry name", false, true, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       return state.access_.add_arguments ? state.access_.add_arguments(state.path())
                                                          : std::vector<libcli2::CompletionItem>{};
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            std::string error;
            if (!state.access_.add || !state.access_.add(state.path(), call.arguments, error)) {
                context.print(error.empty() ? "cannot add entry" : error);
                return -1;
            }
            return 0;
        });

    cli.command("remove")
        .help("Remove one or more entries")
        .available_if([](const libcli2::Context& context) {
            const auto& state = session(context);
            return state.active() && static_cast<bool>(state.access_.remove) && state.access_.collection_kind &&
                   state.access_.collection_kind(state.path()) != ConfigCollectionKind::none;
        })
        .argument({"entry", "Entry name or list index", true, true, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       return state.current_children();
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            std::string error;
            if (!state.access_.remove || !state.access_.remove(state.path(), call.arguments, error)) {
                context.print(error.empty() ? "cannot remove entry" : error);
                return -1;
            }
            return 0;
        });

    cli.command("move")
        .help("Move a list entry")
        .available_if([](const libcli2::Context& context) {
            const auto& state = session(context);
            return state.active() && static_cast<bool>(state.access_.move) && state.access_.can_move &&
                   state.access_.can_move(state.path());
        })
        .argument({"source", "Entry to move", true, false, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       const auto& state = session(request.context);
                       return state.current_children();
                   }})
        .argument({"operation", "up, down, top, bottom, before or after", true, false, {}, {},
                   [](const libcli2::CompletionRequest&) {
                       return std::vector<libcli2::CompletionItem>{{"up", {}}, {"down", {}}, {"top", {}},
                                                                   {"bottom", {}}, {"before", {}}, {"after", {}}};
                   }})
        .argument({"target", "Target entry for before/after", false, false, {}, {},
                   [](const libcli2::CompletionRequest& request) {
                       if (request.arguments.size() < 2 ||
                           (request.arguments[1] != "before" && request.arguments[1] != "after"))
                           return std::vector<libcli2::CompletionItem>{};
                       const auto& state = session(request.context);
                       return state.current_children();
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
            auto& state = session(context);
            if (!state.access_.move || call.arguments.size() < 2) return -1;
            const auto& operation = call.arguments[1];
            const bool needs_target = operation == "before" || operation == "after";
            if (needs_target != (call.arguments.size() == 3)) {
                context.print(needs_target ? "before/after requires a target" : "unexpected move target");
                return -1;
            }
            std::string error;
            const std::string_view target = call.arguments.size() == 3 ? call.arguments[2] : std::string_view{};
            if (!state.access_.move(state.path(), call.arguments[0], operation, target, error)) {
                context.print(error.empty() ? "cannot move entry" : error);
                return -1;
            }
            return 0;
        });

    cli.command("where")
        .help("Show current configuration path")
        .available_if([](const libcli2::Context& context) { return session(context).active(); })
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            const auto value = session(context).path();
            context.print(value.empty() ? "/" : value);
            return 0;
        });

    cli.command("end")
        .help("Leave the current section or configuration mode")
        .available_if([](const libcli2::Context& context) { return session(context).active(); })
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            auto& state = session(context);
            if (state.locations_.size() > 1)
                state.locations_.pop_back();
            else {
                state.locations_.clear();
                state.active_ = false;
                context.mode = "0";
                if (state.access_.leave) state.access_.leave();
            }
            return 0;
        });
}
