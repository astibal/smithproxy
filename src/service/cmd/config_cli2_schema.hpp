#pragma once

#include "config_cli2.hpp"

#include <libconfig.h++>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

namespace smithproxy::config_cli {

bool starts_with(std::string_view value, std::string_view prefix);
bool signature_section(std::string_view path);
bool content_rules_section(std::string_view path);
bool signature_flow_section(std::string_view path);
std::string root_section(std::string_view path);
ConfigCollectionKind collection_kind(std::string_view path);

// Adds one of Smithproxy's ordered entry templates. The operation is atomic.
bool add_ordered_entry(libconfig::Setting& list, std::string_view path,
                       const std::vector<std::string>& arguments, std::string& error);

struct RemovePlan {
    std::vector<int> indexes_descending;
    std::vector<std::string> names;
};

using UsageLookup = std::function<std::vector<std::string>(std::string_view name)>;
bool plan_remove(const libconfig::Setting& collection, ConfigCollectionKind kind,
                 const std::vector<std::string>& entries, const UsageLookup& usage,
                 RemovePlan& plan, std::string& error);

}  // namespace smithproxy::config_cli
