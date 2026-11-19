#pragma once

#include <map>
#include <string>

namespace sx::resources::default_templates {

// Offline migration defaults keyed by their native CFtar paths. Existing
// resources remain authoritative, including deliberately empty templates.
const std::map<std::string, std::string>& all();

} // namespace sx::resources::default_templates
