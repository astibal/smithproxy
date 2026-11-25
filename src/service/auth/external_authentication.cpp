#include "external_authentication.hpp"

#include "runtime_credentials.hpp"

#include <service/admin/auth_socket.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/daemon.hpp>
#include <service/httpd/httpd.hpp>

#include <cstdlib>
#include <exception>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace sx::auth {
namespace {

void report_runtime_credential(
    const bool warning,
    const std::string_view message) {
    DaemonFactory::instance()->get_log().event(
        warning ? WAR : INF,
        "GUI runtime credential: %.*s",
        static_cast<int>(message.size()),
        message.data());
}

void report_auth_socket(
    const bool warning,
    const std::string_view message) {
    DaemonFactory::instance()->get_log().event(
        warning ? WAR : INF,
        "Admin authentication socket: %.*s",
        static_cast<int>(message.size()),
        message.data());
}

void publish_management_api_credentials(
    const RuntimeCredentialSnapshot& snapshot) {
    std::set<std::string> accepted;
    if(snapshot.current) accepted.emplace(*snapshot.current);
    if(snapshot.previous) accepted.emplace(*snapshot.previous);
    sx::webserver::HttpSessions::replace_admin_api_keys(std::move(accepted));
}

void apply_environment_overrides(GuiRuntimeCredentialPolicy& policy) {
    if(const char* override_path = std::getenv("SMITHPROXY_ADMIN_API_KEY_FILE")) {
        policy.management_api.enabled = true;
        policy.management_api.current_path = override_path;
        policy.management_api.previous_path =
            std::string(override_path) + ".previous";
        ::unsetenv("SMITHPROXY_ADMIN_API_KEY_FILE");
    }
    if(const char* socket_path = std::getenv("SMITHPROXY_ADMIN_AUTH_SOCKET")) {
        policy.administrator_auth_socket_enabled = *socket_path != '\0';
        policy.administrator_auth_socket = socket_path;
        ::unsetenv("SMITHPROXY_ADMIN_AUTH_SOCKET");
    }
}

GuiRuntimeCredentialPolicy load_policy() {
    const auto tenant_index = CfgFactory::get()->tenant_index;
    auto policy = default_gui_runtime_credentials(tenant_index);
    if(CfgFactory::get()->using_native_archive()) {
        try {
            const auto resource = CfgFactory::get()->resolve_resource("gui.cfg", {});
            policy = parse_gui_runtime_credentials(resource.content(), tenant_index);
        }
        catch(const std::exception& error) {
            DaemonFactory::instance()->get_log().event(
                WAR,
                "GUI runtime credential policy is invalid; using secure defaults: %s",
                error.what());
        }
    }

    apply_environment_overrides(policy);
    return policy;
}

class ExternalAuthenticationManager {
public:
    explicit ExternalAuthenticationManager(GuiRuntimeCredentialPolicy policy)
        : policy_(std::move(policy)),
          management_api_credential_(
              policy_.management_api,
              publish_management_api_credentials,
              report_runtime_credential),
          gateway_credential_(
              policy_.gateway,
              [](const RuntimeCredentialSnapshot&) {},
              report_runtime_credential),
          admin_auth_socket_(
              policy_.administrator_auth_socket,
              sx::admin::authenticate,
              report_auth_socket) {}

    ~ExternalAuthenticationManager() { stop(); }

    void start() {
        management_api_credential_.reconcile();
        gateway_credential_.reconcile();
        management_api_credential_.start();
        gateway_credential_.start();

        const bool socket_required =
            policy_.administrator_auth_socket_enabled;
        const bool socket_started =
            !socket_required || admin_auth_socket_.start();
        if(!socket_started) {
            DaemonFactory::instance()->get_log().event(
                WAR,
                "local administrator authentication socket is unavailable");
        }
    }

    void stop() noexcept {
        admin_auth_socket_.stop();
        management_api_credential_.stop();
        gateway_credential_.stop();
    }

private:
    GuiRuntimeCredentialPolicy policy_;
    RuntimeCredentialPair management_api_credential_;
    RuntimeCredentialPair gateway_credential_;
    sx::admin::AuthSocket admin_auth_socket_;
};

std::mutex manager_mutex;
std::unique_ptr<ExternalAuthenticationManager> manager;

} // namespace

void manage_external_authentication() {
    auto lock = std::scoped_lock(manager_mutex);
    if(manager) return;

    auto next = std::make_unique<ExternalAuthenticationManager>(load_policy());
    next->start();
    manager = std::move(next);
}

void stop_external_authentication() noexcept {
    std::unique_ptr<ExternalAuthenticationManager> active;
    {
        auto lock = std::scoped_lock(manager_mutex);
        active = std::move(manager);
    }
}

} // namespace sx::auth
