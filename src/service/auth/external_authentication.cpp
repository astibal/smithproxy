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

struct ExternalAuthenticationPolicy {
    GuiRuntimeCredentialPolicy runtime_credentials;
    bool admin_socket_enabled {true};
    std::filesystem::path admin_socket_path;
};

std::filesystem::path default_admin_socket_path(const unsigned int tenant_index) {
    auto directory = std::filesystem::path("/run/smithproxy");
    if(tenant_index != 0U) {
        directory /= "tenant-" + std::to_string(tenant_index);
    }
    return directory / "admin-auth.sock";
}

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
    // Accept both generations during the bounded overlap window. HttpSessions
    // performs the actual request-time API key authorization.
    std::set<std::string> accepted;
    if(snapshot.current) accepted.emplace(*snapshot.current);
    if(snapshot.previous) accepted.emplace(*snapshot.previous);
    sx::webserver::HttpSessions::replace_admin_api_keys(std::move(accepted));
}

void apply_environment_overrides(ExternalAuthenticationPolicy& policy) {
    if(const char* override_path = std::getenv("SMITHPROXY_ADMIN_API_KEY_FILE")) {
        policy.runtime_credentials.management_api.enabled = true;
        policy.runtime_credentials.management_api.current_path = override_path;
        policy.runtime_credentials.management_api.previous_path =
            std::string(override_path) + ".previous";
        ::unsetenv("SMITHPROXY_ADMIN_API_KEY_FILE");
    }
    if(const char* socket_path = std::getenv("SMITHPROXY_ADMIN_AUTH_SOCKET")) {
        policy.admin_socket_enabled = *socket_path != '\0';
        if(policy.admin_socket_enabled) {
            policy.admin_socket_path = socket_path;
        }
        ::unsetenv("SMITHPROXY_ADMIN_AUTH_SOCKET");
    }
}

ExternalAuthenticationPolicy load_policy() {
    // GUI owns runtime API credential policy. Core admin configuration owns
    // the transport used by SSH, CLI and other local management clients.
    const auto tenant_index = CfgFactory::get()->tenant_index;
    ExternalAuthenticationPolicy policy;
    policy.runtime_credentials = default_gui_runtime_credentials(tenant_index);
    policy.admin_socket_path = default_admin_socket_path(tenant_index);
    if(CfgFactory::get()->using_native_archive()) {
        try {
            const auto resource = CfgFactory::get()->resolve_resource("gui.cfg", {});
            policy.runtime_credentials =
                parse_gui_runtime_credentials(resource.content(), tenant_index);
        }
        catch(const std::exception& error) {
            DaemonFactory::instance()->get_log().event(
                WAR,
                "GUI runtime credential policy is invalid; using secure defaults: %s",
                error.what());
        }

        try {
            const auto admins = CfgFactory::administrator_config();
            policy.admin_socket_enabled = admins.authentication().socket_enabled;
            if(admins.authentication().socket_path) {
                policy.admin_socket_path = *admins.authentication().socket_path;
            }
        }
        catch(const std::exception& error) {
            DaemonFactory::instance()->get_log().event(
                WAR,
                "administrator authentication policy is invalid; using secure defaults: %s",
                error.what());
        }
    }

    apply_environment_overrides(policy);
    return policy;
}

class AdminAuthProvider {
public:
    explicit AdminAuthProvider(ExternalAuthenticationPolicy policy):
        policy_(std::move(policy)),
        management_api_credential_(
            policy_.runtime_credentials.management_api,
            publish_management_api_credentials,
            report_runtime_credential),
        gateway_credential_(
            policy_.runtime_credentials.gateway,
            [](const RuntimeCredentialSnapshot&) {},
            report_runtime_credential),
        admin_auth_socket_(
            policy_.admin_socket_path,
            sx::admin::authenticate,
            report_auth_socket) {}

    ~AdminAuthProvider() { stop(); }

    void start() {
        // Reconcile synchronously so the API does not wait for the first worker
        // interval before receiving its accepted credential generations.
        management_api_credential_.reconcile();
        gateway_credential_.reconcile();
        management_api_credential_.start();
        gateway_credential_.start();

        const bool socket_required = policy_.admin_socket_enabled;
        const bool socket_started =
            !socket_required || admin_auth_socket_.start();
        if(!socket_started) {
            DaemonFactory::instance()->get_log().event(
                WAR,
                "local administrator authentication socket is unavailable");
        }
    }

    void stop() noexcept {
        // Stop new local authentication first, then retire credential workers.
        admin_auth_socket_.stop();
        management_api_credential_.stop();
        gateway_credential_.stop();
    }

private:
    ExternalAuthenticationPolicy policy_;
    RuntimeCredentialPair management_api_credential_;
    RuntimeCredentialPair gateway_credential_;
    sx::admin::AuthSocket admin_auth_socket_;
};

std::mutex manager_mutex;
std::unique_ptr<AdminAuthProvider> provider;

} // namespace

void manage_external_authentication(const bool gui_enabled) {
    // Keep main() independent of credential and socket implementation details.
    // The singleton lifetime also makes repeated lifecycle calls harmless.
    auto lock = std::scoped_lock(manager_mutex);
    if(provider) {
        return;
    }

    auto policy = load_policy();
    if(!gui_enabled) {
        // Keep local administrator authentication available to SSH while
        // continuously withdrawing both GUI-facing credential generations.
        // Apply this after every config and environment input so --no-gui
        // remains the final process-level authority.
        policy.runtime_credentials.management_api.enabled = false;
        policy.runtime_credentials.gateway.enabled = false;
        DaemonFactory::instance()->get_log().event(
            INF,
            "management GUI disabled: GUI and gateway credentials are withdrawn; "
            "local administrator authentication remains available");
    }

    auto next = std::make_unique<AdminAuthProvider>(std::move(policy));
    next->start();
    provider = std::move(next);
}

void stop_external_authentication() noexcept {
    std::unique_ptr<AdminAuthProvider> active;
    {
        auto lock = std::scoped_lock(manager_mutex);
        active = std::move(provider);
    }
}

} // namespace sx::auth
