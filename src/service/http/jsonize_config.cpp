#include "jsonize.hpp"

#include <sstream>

namespace jsonize {

namespace {

std::string scalar_string(libconfig::Setting const& setting) {
    std::stringstream value;
    switch (setting.getType()) {
        case libconfig::Setting::TypeInt: value << static_cast<int>(setting); break;
        case libconfig::Setting::TypeInt64: value << static_cast<long long>(setting); break;
        case libconfig::Setting::TypeString: value << static_cast<const char*>(setting); break;
        case libconfig::Setting::TypeFloat: value << static_cast<double>(setting); break;
        case libconfig::Setting::TypeBoolean: value << static_cast<bool>(setting); break;
        default: break;
    }
    return value.str();
}

} // namespace

nlohmann::json from(libconfig::Setting const& setting) {
    if (setting.isScalar())
        return scalar_string(setting);

    nlohmann::json result = setting.getType() == libconfig::Setting::TypeList
                            ? nlohmann::json::array()
                            : nlohmann::json::object();

    for (int i = 0; i < setting.getLength(); ++i) {
        auto const& child = setting[i];
        nlohmann::json value;

        if (child.getType() == libconfig::Setting::TypeArray) {
            value = nlohmann::json::array();
            for (int j = 0; j < child.getLength(); ++j)
                value.push_back(scalar_string(child[j]));
        } else {
            value = from(child);
        }

        if (setting.getType() == libconfig::Setting::TypeList || child.getName() == nullptr)
            result.push_back(std::move(value));
        else
            result[child.getName()] = std::move(value);
    }

    return result;
}

} // namespace jsonize
