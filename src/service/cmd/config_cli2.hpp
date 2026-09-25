#pragma once

#include <ext/libcli2/cli.hpp>

#include <libconfig.h++>

#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

enum class ConfigCollectionKind {
    none,
    named_objects,
    ordered_objects,
};

struct ConfigCli2Access {
    using ValueOperation = std::function<bool(std::string_view path, std::string_view property,
                                              const std::vector<std::string>& values, std::string& error)>;

    std::function<libconfig::Setting&()> root;
    // Protects traversal while another Smithproxy thread may replace/reload
    // parts of the live libconfig tree. Optional for standalone users/tests.
    std::recursive_mutex* mutex = nullptr;
    std::function<std::vector<libcli2::CompletionItem>(std::string_view path, std::string_view property)> values;
    std::function<std::vector<libcli2::CompletionItem>(std::string_view path)> add_arguments;
    std::function<ConfigCollectionKind(std::string_view path)> collection_kind;
    std::function<bool(std::string_view path)> can_add;
    std::function<bool(std::string_view path)> can_move;
    ValueOperation set;
    ValueOperation toggle;
    std::function<bool(std::string_view path, const std::vector<std::string>& arguments, std::string& error)> add;
    std::function<bool(std::string_view path, const std::vector<std::string>& entries, std::string& error)> remove;
    std::function<bool(std::string_view path, std::string_view source, std::string_view operation,
                       std::string_view target, std::string& error)> move;
    std::function<void()> enter;
    std::function<void()> leave;
};

class ConfigCli2Session {
public:
    explicit ConfigCli2Session(ConfigCli2Access access);

    void register_commands(libcli2::Cli& cli);
    void reset() noexcept { active_ = false; locations_.clear(); }
    bool active() const noexcept { return active_; }
    std::string path() const;

private:
    libconfig::Setting* current() const;
    libconfig::Setting* resolve(const std::vector<std::string>& components) const;
    bool enter_path(const std::vector<std::string>& components);
    std::vector<libcli2::CompletionItem> children_at(const std::vector<std::string>& components) const;
    std::vector<libcli2::CompletionItem> current_children() const;
    std::vector<libcli2::CompletionItem> children(const libconfig::Setting& setting) const;
    bool navigable(const libconfig::Setting& setting) const;
    std::vector<libcli2::CompletionItem> properties() const;
    std::vector<libcli2::CompletionItem> toggle_properties() const;

    ConfigCli2Access access_;
    bool active_ = false;
    std::vector<std::string> locations_;
};
