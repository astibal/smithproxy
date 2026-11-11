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

    // restart_required distinguishes a restored startup archive from ordinary
    // unsaved running changes. In the former case save is intentionally blocked
    // because it would overwrite the restored bytes before activation.
    return {
        {"state", "ready"},
        {"revision", revisions.current_id},
        {"saved_revision", revisions.saved_id},
        {"unsaved", revisions.unsaved},
        {"restart_required", CfgFactory::get()->startup_archive_pending()},
        {"archive_monitor_error", CfgFactory::get()->archive_monitor_error()},
        {"capabilities", {
            {"explicit_save", true},
            {"archive_restore", true},
        }},
        {"config", std::move(config)},
    };
}

}  // namespace sx::webserver
