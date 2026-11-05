#include "cfg_tx.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <optional>
#include <set>
#include <type_traits>
#include <utility>

#include "cfg_serialization.hpp"

namespace sx::cfg::tx {
namespace {

Issue issue(std::size_t operation,
            std::string code,
            std::string path,
            std::string detail) {
    return Issue {
        operation,
        std::move(code),
        std::move(path),
        std::move(detail),
    };
}

// Local C++17 spelling of std::unexpected. Result converts the returned Issue
// into its error state at the caller's return boundary.
Issue unexpected(Issue value) {
    return value;
}

bool fits_int(std::int64_t value) {
    return value >= std::numeric_limits<int>::min() &&
           value <= std::numeric_limits<int>::max();
}

// libconfig distinguishes its historical 32-bit integer from TypeInt64.
// Preserve the smaller representation whenever every supplied value fits.
libconfig::Setting::Type integer_type(std::vector<std::int64_t> const& values) {
    return std::all_of(values.begin(), values.end(), fits_int)
        ? libconfig::Setting::TypeInt
        : libconfig::Setting::TypeInt64;
}

// Select the libconfig setting created for a previously missing property.
// Existing properties keep their original type and use the matching checks
// below instead.
libconfig::Setting::Type value_type(Value const& value) {
    return std::visit([](auto const& typed) {
        using Type = std::decay_t<decltype(typed)>;
        if constexpr(std::is_same_v<Type, std::int64_t>) {
            return fits_int(typed)
                ? libconfig::Setting::TypeInt
                : libconfig::Setting::TypeInt64;
        } else if constexpr(std::is_same_v<Type, double>) {
            return libconfig::Setting::TypeFloat;
        } else if constexpr(std::is_same_v<Type, bool>) {
            return libconfig::Setting::TypeBoolean;
        } else if constexpr(std::is_same_v<Type, std::string>) {
            return libconfig::Setting::TypeString;
        } else {
            return libconfig::Setting::TypeArray;
        }
    }, value);
}

bool is_array(Value const& value) {
    return value.index() >= 4;
}

// Integer input may target either libconfig integer width. Other scalar types
// must match exactly; silently converting a string such as "false" to bool
// would defeat the typed transaction contract.
bool scalar_matches(libconfig::Setting::Type type, Value const& value) {
    if(is_array(value)) return false;
    if(std::holds_alternative<std::int64_t>(value)) {
        return type == libconfig::Setting::TypeInt ||
               type == libconfig::Setting::TypeInt64;
    }
    return type == value_type(value);
}

// Validate the complete replacement before removing the old array. This is
// what keeps a failed Set operation from partially mutating the candidate.
bool array_matches(libconfig::Setting::Type type, Value const& value) {
    if(auto const* values = std::get_if<std::vector<std::int64_t>>(&value)) {
        if(type == libconfig::Setting::TypeInt) {
            return std::all_of(values->begin(), values->end(), fits_int);
        }
        return type == libconfig::Setting::TypeInt64;
    }
    if(std::holds_alternative<std::vector<double>>(value)) {
        return type == libconfig::Setting::TypeFloat;
    }
    if(std::holds_alternative<std::vector<bool>>(value)) {
        return type == libconfig::Setting::TypeBoolean;
    }
    if(std::holds_alternative<std::vector<std::string>>(value)) {
        return type == libconfig::Setting::TypeString;
    }
    return false;
}

// Assign only after scalar_matches() accepted the pairing. The remaining
// integer range check protects a TypeInt setting from narrowing overflow.
bool assign_scalar(libconfig::Setting& setting, Value const& value) {
    return std::visit([&setting](auto const& typed) {
        using Type = std::decay_t<decltype(typed)>;
        if constexpr(std::is_same_v<Type, std::int64_t>) {
            if(setting.getType() == libconfig::Setting::TypeInt) {
                if(!fits_int(typed)) return false;
                setting = static_cast<int>(typed);
            } else {
                setting = static_cast<long long>(typed);
            }
            return true;
        } else if constexpr(std::is_same_v<Type, double> ||
                            std::is_same_v<Type, bool> ||
                            std::is_same_v<Type, std::string>) {
            setting = typed;
            return true;
        } else {
            return false;
        }
    }, value);
}

// libconfig exposes integer assignment through two distinct overloads, so the
// selected array element width has to be reflected at each append.
void append_integer(libconfig::Setting& array,
                    libconfig::Setting::Type type,
                    std::int64_t value) {
    if(type == libconfig::Setting::TypeInt) {
        array.add(type) = static_cast<int>(value);
    } else {
        array.add(type) = static_cast<long long>(value);
    }
}

// Materialize a typed vector in a libconfig array. This helper deliberately
// accepts no scalar alternatives and therefore cannot create a mixed array.
bool append_array(libconfig::Setting& array,
                  libconfig::Setting::Type element_type,
                  Value const& value) {
    return std::visit([&array, element_type](auto const& values) {
        using Type = std::decay_t<decltype(values)>;
        if constexpr(std::is_same_v<Type, std::vector<std::int64_t>>) {
            if(element_type == libconfig::Setting::TypeInt &&
               !std::all_of(values.begin(), values.end(), fits_int)) return false;
            for(auto item : values) append_integer(array, element_type, item);
            return true;
        } else if constexpr(std::is_same_v<Type, std::vector<double>> ||
                            std::is_same_v<Type, std::vector<bool>> ||
                            std::is_same_v<Type, std::vector<std::string>>) {
            for(auto const& item : values) {
                if constexpr(std::is_same_v<Type, std::vector<bool>>) {
                    array.add(element_type) = static_cast<bool>(item);
                } else {
                    array.add(element_type) = item;
                }
            }
            return true;
        } else {
            return false;
        }
    }, value);
}

// Empty libconfig arrays do not retain an element type. The typed transaction
// value supplies that missing information when an array is created or reset.
libconfig::Setting::Type array_element_type(Value const& value) {
    if(auto const* values = std::get_if<std::vector<std::int64_t>>(&value)) {
        return integer_type(*values);
    }
    if(std::holds_alternative<std::vector<double>>(value)) {
        return libconfig::Setting::TypeFloat;
    }
    if(std::holds_alternative<std::vector<bool>>(value)) {
        return libconfig::Setting::TypeBoolean;
    }
    return libconfig::Setting::TypeString;
}

void clone_value(libconfig::Setting& destination,
                 libconfig::Setting const& source);

// libconfig has no public deep-copy operation. Move needs one because list
// elements cannot be reordered in place without first preserving their data.
void clone_children(libconfig::Setting& destination,
                    libconfig::Setting const& source) {
    for(int index = 0; index < source.getLength(); ++index) {
        auto const& child = source[index];
        auto const type = child.getType();
        auto const* name = child.getName();
        auto& copy = name
            ? destination.add(name, type)
            : destination.add(type);

        clone_value(copy, child);
    }
}

void clone_value(libconfig::Setting& destination,
                 libconfig::Setting const& source) {
    if(source.isAggregate()) {
        clone_children(destination, source);
        return;
    }

    switch(source.getType()) {
        case libconfig::Setting::TypeInt: destination = static_cast<int>(source); break;
        case libconfig::Setting::TypeInt64: destination = static_cast<long long>(source); break;
        case libconfig::Setting::TypeFloat: destination = static_cast<double>(source); break;
        case libconfig::Setting::TypeBoolean: destination = static_cast<bool>(source); break;
        case libconfig::Setting::TypeString: destination = static_cast<char const*>(source); break;
        default: break;
    }
}

Candidate::ApplyResult apply_set(libconfig::Config& config,
                                 Set const& operation,
                                 std::size_t index) {
    if(operation.path.empty()) {
        return unexpected(issue(index, "empty_path", {}, "Set path must not be empty"));
    }

    libconfig::Setting* setting = nullptr;
    try {
        setting = &config.lookup(operation.path);
    } catch(libconfig::SettingNotFoundException const&) {
        // A preceding Add may have created an empty group. Set is therefore
        // allowed to create its final, explicitly typed property, but never
        // an implicit chain of missing parent groups.
        auto const separator = operation.path.rfind('.');
        auto const parent_path = separator == std::string::npos
            ? std::string {}
            : operation.path.substr(0, separator);
        auto const name = separator == std::string::npos
            ? operation.path
            : operation.path.substr(separator + 1);
        if(name.empty()) {
            return unexpected(issue(
                index, "invalid_path", operation.path, "Set path has no property name"));
        }

        libconfig::Setting* parent = nullptr;
        try {
            parent = parent_path.empty()
                ? &config.getRoot()
                : &config.lookup(parent_path);
        } catch(libconfig::SettingNotFoundException const&) {
            return unexpected(issue(
                index, "unknown_path", operation.path, "Configuration parent does not exist"));
        }
        if(parent->getType() != libconfig::Setting::TypeGroup) {
            return unexpected(issue(
                index, "unsupported_type", parent_path, "New properties require a group parent"));
        }

        auto const type = value_type(operation.value);
        try {
            setting = &parent->add(name, type);
        } catch(libconfig::SettingException const& exception) {
            return unexpected(issue(index, "invalid_path", operation.path, exception.what()));
        }
        if(type == libconfig::Setting::TypeArray) {
            auto const element_type = array_element_type(operation.value);
            if(!append_array(*setting, element_type, operation.value)) {
                return unexpected(issue(
                    index, "invalid_type", operation.path, "Array value cannot be stored"));
            }
        } else if(!assign_scalar(*setting, operation.value)) {
            return unexpected(issue(
                index, "invalid_type", operation.path, "Scalar value cannot be stored"));
        }
        return {};
    }

    // Existing settings are stricter than new leaves: their libconfig type is
    // part of the snapshot schema and must not change during a Set operation.
    auto const type = setting->getType();
    if(setting->isScalar()) {
        if(!scalar_matches(type, operation.value)) {
            return unexpected(issue(
                index, "type_mismatch", operation.path, "Value type does not match the scalar setting"));
        }
        if(!assign_scalar(*setting, operation.value)) {
            return unexpected(issue(
                index, "invalid_type", operation.path, "Value cannot be converted to the setting type"));
        }
        return {};
    }

    if(type != libconfig::Setting::TypeArray) {
        return unexpected(issue(
            index, "unsupported_type", operation.path, "Set supports scalar settings and arrays"));
    }

    if(!is_array(operation.value)) {
        return unexpected(issue(
            index, "type_mismatch", operation.path, "Array setting requires an array value"));
    }
    auto const element_type = setting->getLength() > 0
        ? (*setting)[0].getType()
        : array_element_type(operation.value);
    if(!array_matches(element_type, operation.value)) {
        return unexpected(issue(
            index, "type_mismatch", operation.path, "Array element type does not match the setting"));
    }

    while(setting->getLength() > 0) setting->remove(setting->getLength() - 1);
    if(!append_array(*setting, element_type, operation.value)) {
        return unexpected(issue(
            index, "invalid_type", operation.path, "Array value cannot be stored"));
    }
    return {};
}

Candidate::ApplyResult apply_add(libconfig::Config& config,
                                 Add const& operation,
                                 std::size_t index) {
    if(operation.path.empty()) {
        return unexpected(issue(index, "empty_path", {}, "Add path must not be empty"));
    }

    libconfig::Setting* parent = nullptr;
    try {
        parent = &config.lookup(operation.path);
    } catch(libconfig::SettingNotFoundException const&) {
        return unexpected(issue(
            index, "unknown_path", operation.path, "Configuration collection does not exist"));
    }

    try {
        // Named collections are groups; unnamed collections such as policy
        // are lists. Add creates only the container. Later typed Set
        // operations populate it before final domain validation.
        if(parent->getType() == libconfig::Setting::TypeGroup) {
            if(operation.name.empty()) {
                return unexpected(issue(
                    index, "empty_name", operation.path, "Named collection requires an entry name"));
            }
            if(operation.name.rfind("__", 0) == 0) {
                return unexpected(issue(
                    index, "reserved_name", operation.path, "Entry name must not start with '__'"));
            }
            if(parent->exists(operation.name)) {
                return unexpected(issue(
                    index, "duplicate_entry", operation.path, "Entry already exists: " + operation.name));
            }
            parent->add(operation.name, libconfig::Setting::TypeGroup);
            return {};
        }
        if(parent->getType() == libconfig::Setting::TypeList) {
            parent->add(libconfig::Setting::TypeGroup);
            return {};
        }
    } catch(libconfig::SettingException const& exception) {
        return unexpected(issue(index, "add_failed", operation.path, exception.what()));
    }

    return unexpected(issue(
        index, "unsupported_type", operation.path, "Add requires a group or list collection"));
}

Candidate::ApplyResult apply_remove(libconfig::Config& config,
                                    Remove const& operation,
                                    std::size_t index) {
    if(operation.entries.empty()) {
        return unexpected(issue(
            index, "empty_entries", operation.path, "Remove requires at least one entry"));
    }

    libconfig::Setting* parent = nullptr;
    try {
        parent = &config.lookup(operation.path);
    } catch(libconfig::SettingNotFoundException const&) {
        return unexpected(issue(
            index, "unknown_path", operation.path, "Configuration collection does not exist"));
    }

    if(parent->getType() == libconfig::Setting::TypeGroup) {
        // Validate the whole request before deleting anything. In particular,
        // repeated names must not turn the second removal into a partial fail.
        std::set<std::string> unique_entries;
        for(auto const& entry : operation.entries) {
            if(!unique_entries.insert(entry).second) {
                return unexpected(issue(
                    index, "duplicate_entry", operation.path, "Entry is repeated: " + entry));
            }
            if(!parent->exists(entry)) {
                return unexpected(issue(
                    index, "unknown_entry", operation.path, "Entry does not exist: " + entry));
            }
        }
        for(auto const& entry : operation.entries) parent->remove(entry);
        return {};
    }

    if(parent->getType() != libconfig::Setting::TypeList) {
        return unexpected(issue(
            index, "unsupported_type", operation.path, "Remove requires a group or list collection"));
    }

    // List indices are removed from highest to lowest so earlier removals do
    // not shift the positions of entries which still have to be deleted.
    std::vector<int> positions;
    positions.reserve(operation.entries.size());
    for(auto const& entry : operation.entries) {
        int position = -1;
        auto const result = std::from_chars(entry.data(), entry.data() + entry.size(), position);
        if(result.ec != std::errc {} || result.ptr != entry.data() + entry.size() ||
           position < 0 || position >= parent->getLength()) {
            return unexpected(issue(
                index, "invalid_index", operation.path, "List index is invalid: " + entry));
        }
        positions.push_back(position);
    }
    std::sort(positions.begin(), positions.end());
    if(std::adjacent_find(positions.begin(), positions.end()) != positions.end()) {
        return unexpected(issue(
            index, "duplicate_entry", operation.path, "List index is repeated"));
    }
    for(auto position = positions.rbegin(); position != positions.rend(); ++position) {
        parent->remove(*position);
    }
    return {};
}

Candidate::ApplyResult apply_move(libconfig::Config& config,
                                  Move const& operation,
                                  std::size_t index) {
    libconfig::Setting* list = nullptr;
    try {
        list = &config.lookup(operation.path);
    } catch(libconfig::SettingNotFoundException const&) {
        return unexpected(issue(
            index, "unknown_path", operation.path, "Configuration list does not exist"));
    }

    if(list->getType() != libconfig::Setting::TypeList) {
        return unexpected(issue(
            index, "unsupported_type", operation.path, "Move requires a list collection"));
    }
    auto const length = static_cast<std::size_t>(list->getLength());
    if(operation.source >= length || operation.target >= length) {
        return unexpected(issue(
            index, "invalid_index", operation.path, "Move index is outside the list"));
    }
    if(operation.source == operation.target) return {};

    // Build the desired order as source indices first. Nothing in the
    // candidate list changes until every element has been cloned successfully.
    std::vector<std::size_t> order;
    order.reserve(length);
    for(std::size_t current = 0; current < length; ++current) {
        if(current != operation.source) order.push_back(current);
    }
    auto target = std::find(order.begin(), order.end(), operation.target);
    if(operation.position == Position::after) ++target;
    order.insert(target, operation.source);

    // The scratch config owns a deep copy while the original list is cleared
    // and rebuilt. This is necessary because libconfig has no list splice.
    libconfig::Config scratch;
    auto& copy = scratch.getRoot().add("items", libconfig::Setting::TypeList);
    for(auto position : order) {
        auto const& source = (*list)[static_cast<int>(position)];
        auto& item = copy.add(source.getType());
        clone_value(item, source);
    }
    while(list->getLength() > 0) list->remove(list->getLength() - 1);
    clone_children(*list, copy);
    return {};
}

}  // namespace

Candidate::Candidate(std::unique_ptr<libconfig::Config> config)
    : config_(std::move(config)) {}

Candidate::LoadResult Candidate::load(std::string const& snapshot) {
    auto config = std::make_unique<libconfig::Config>();
    try {
        config->readString(snapshot);
    } catch(libconfig::ParseException const& exception) {
        return unexpected(issue(
            0,
            "invalid_snapshot",
            {},
            "libconfig parse error on line " + std::to_string(exception.getLine()) +
                ": " + exception.getError()));
    }
    return Candidate(std::move(config));
}

Candidate::ApplyResult Candidate::apply(Op const& operation,
                                        std::size_t operation_index) {
    return std::visit(
        [this, operation_index](auto const& value) -> ApplyResult {
            using Value = std::decay_t<decltype(value)>;
            if constexpr(std::is_same_v<Value, Set>) {
                return apply_set(*config_, value, operation_index);
            } else if constexpr(std::is_same_v<Value, Add>) {
                return apply_add(*config_, value, operation_index);
            } else if constexpr(std::is_same_v<Value, Remove>) {
                return apply_remove(*config_, value, operation_index);
            } else {
                return apply_move(*config_, value, operation_index);
            }
        },
        operation);
}

Candidate::SnapshotResult Candidate::snapshot() {
    auto serialized = cfgapi_detail::serialize_config(*config_);
    if(!serialized) {
        return unexpected(issue(
            0, "serialization_failed", {}, "Candidate configuration cannot be serialized"));
    }

    // Parsing the serialized bytes catches any result which libconfig could
    // write but not reconstruct. The returned snapshot is therefore suitable
    // for revision history and the later commit stage.
    libconfig::Config verification;
    try {
        verification.readString(*serialized);
    } catch(libconfig::ParseException const& exception) {
        return unexpected(issue(
            0,
            "serialization_failed",
            {},
            "Serialized candidate cannot be parsed on line " +
                std::to_string(exception.getLine()) + ": " + exception.getError()));
    }
    return *serialized;
}

libconfig::Config const& Candidate::config() const noexcept {
    return *config_;
}

}  // namespace sx::cfg::tx
