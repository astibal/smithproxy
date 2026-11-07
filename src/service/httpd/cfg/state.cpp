#include "state.hpp"

#include <mutex>

#include <service/cfgapi/cfgapi.hpp>
#include <service/http/jsonize.hpp>

namespace sx::webserver {

nlohmann::json cfg_state(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    [[maybe_unused]] std::string const& request) {
    // Commit installs running config before advancing UpdateBoard. Holding the
    // same config mutex across both reads prevents clients from receiving a
    // config body paired with either the preceding or following revision.
    std::scoped_lock config_lock(CfgFactory::lock());
    auto const revisions = CfgFactory::board()->revision_state();
    auto config = jsonize::from(CfgFactory::cfg_root());

    return {
        {"state", "ready"},
        {"revision", revisions.current_id},
        {"saved_revision", revisions.saved_id},
        {"unsaved", revisions.unsaved},
        {"config", std::move(config)},
    };
}

}  // namespace sx::webserver
