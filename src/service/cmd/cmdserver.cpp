#include "cmdserver.hpp"
#include "cli_client_tasks.hpp"

#include "cli_debug_state.hpp"
#include "config_cli2_smithproxy.hpp"
#include "libcli2_socket.hpp"
#include "smith_cli2_commands.hpp"

#include <service/cfgapi/cfgapi.hpp>
#include <service/core/authpam.hpp>
#include <service/core/smithproxy.hpp>

#include <inspect/dnsinspector.hpp>
#include <log/logger.hpp>
#include <proxy/mitmproxy.hpp>
#include <socle.hpp>
#include <privileged_socket.hpp>
#include <sslcom.hpp>
#include <sslcertstore.hpp>
#include <utils/str.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

struct CliGlobals {
    static std::string create_hostname() {
        char hostname[64]{};
        gethostname(hostname, sizeof(hostname) - 1);
        const auto tenant = "." + CfgFactory::get()->tenant_name;
        return hostname + (tenant == ".default" ? std::string{} : tenant);
    }
    static const std::string& hostname() {
        static const std::string value = create_hostname();
        return value;
    }
    static thread_local inline std::chrono::steady_clock::time_point
        ct_warning_next{};
    static thread_local inline bool cfg_error_flag = false;
};

constexpr auto ct_warning_interval = std::chrono::minutes(5);

bool ct_is_requested() {
    const auto lock = std::scoped_lock(CfgFactory::lock());
    return CfgFactory::get()->ct_requested();
}

std::string prompt(const libcli2::Context& context) {
    const auto d = context.decor();
    auto board = CfgFactory::board();
    board->ack_current(cli_id());
    board->ack_saved(cli_id());
    const bool unsaved = board->at(cli_id()).seen_current != board->at(cli_id()).seen_saved;
    // Keep the wire-safe ASCII name when colors are disabled. An active palette
    // implies a modern terminal, so the colored prompt can use U+2300 as the
    // terminal-sized counterpart of the Smithproxy mark.
    std::string brand = "smithproxy";
    if (context.colors_enabled()) {
        brand = d.command("smithpr") + d.success("\xE2\x8C\x80") + d.command("xy");
    }
    std::string value = brand + "(" + d.key(CliGlobals::hostname()) + ")";
    if (unsaved) value += d.warning("<*>");
    if (CfgFactory::LOAD_ERRORS) value += d.error("<!>");
    if (context.mode != "0") {
        const auto* config = static_cast<const ConfigCli2Session*>(context.user_data);
        const auto path = config ? config->path() : std::string{};
        value += d.command(path.empty() ? "(config:/)" : "(config:/" + path + ")");
    }
    value += context.privilege >= 15 ? d.warning("# ") : d.muted("> ");
    return value;
}

void load_defaults() {
    auto& state = CliDebugState::get();
    state.orig_ssl_loglevel = SSLCom::log_level();
    state.orig_sslmitm_loglevel = SSLMitmCom::log_level();
    state.orig_sslca_loglevel = *SSLFactory::get_log().level();
    state.orig_dns_insp_loglevel = DNS_Inspector::log_level();
    state.orig_dns_packet_loglevel = DNS_Packet::log_level();
    state.orig_baseproxy_loglevel = baseProxy::log_level();
    state.orig_epoll_loglevel = epoll::log_level;
    state.orig_mitmproxy_loglevel = MitmProxy::log_level();
    state.orig_mitmmasterproxy_loglevel = MitmMasterProxy::log_level();
}

int regular(libcli2::Context& context) {
    auto board = CfgFactory::board();
    if (board->differs(cli_id())) {
        board->ack_current(cli_id());
        board->ack_saved(cli_id());
        if (board->updater() != cli_id()) {
            context.mode = "0";
            static_cast<ConfigCli2Session*>(context.user_data)->reset();
        }
    }
    if (SmithProxy::instance().terminate_flag) {
        context.print(context.decor().error("\n !!!   Shutdown   !!!"));
        return 1;
    }
    if (CfgFactory::LOAD_ERRORS && !CliGlobals::cfg_error_flag) {
        const auto d = context.decor();
        context.print(d.warning("Warning: There was a problem loading configuration") + "\n    - execute " +
                      d.command("show event list") + " to see more details");
        CliGlobals::cfg_error_flag = true;
    }
    const bool ct_unavailable = ct_is_requested() &&
                                !SSLFactory::factory().is_ct_available();
    const auto now = std::chrono::steady_clock::now();
    if(ct_unavailable && now >= CliGlobals::ct_warning_next) {
        const auto d = context.decor();
        context.print(d.warning(std::string("Warning: ") +
                      CfgFactory::CT_UNAVAILABLE_WARNING.data()) +
                      "\n    - download it using " +
                      d.command("sx_download_ctlog") + " and restart service");
        CliGlobals::ct_warning_next = now + ct_warning_interval;
    } else if(!ct_unavailable) {
        CliGlobals::ct_warning_next = {};
    }
    return 0;
}

void client_thread(int client_socket) {
    libcli2::FdTransport transport(libcli2::FdPair(client_socket, client_socket));
    std::string admin_group;
    std::string enable_password;
    {
        const auto lock = std::scoped_lock(CfgFactory::get()->lock());
        admin_group = CfgFactory::get()->admin_group;
        enable_password = CfgFactory::get()->cli_enable_password;
    }
    UpdateBoardSubscriber subscriber(cli_id(), CfgFactory::board());
    Log::get()->events().insert(NOT, "admin CLI access");
    Log::get()->remote_targets(string_format("cli-%d", client_socket), client_socket);
    auto profile = std::make_unique<logger_profile>();
    profile->level_ = CfgFactory::get()->cli_init_level;
    Log::get()->target_profiles()[static_cast<std::uint64_t>(client_socket)] = std::move(profile);
    load_defaults();

    Libcli2SocketOptions options;
    options.banner = "--==[ Smithproxy command line utility ]==--";
    options.enable_password = std::move(enable_password);
    options.config_access = make_smithproxy_config_access(cli_id());
    options.prompt = prompt;
    options.regular = regular;
    options.register_commands = [](libcli2::Cli& cli) {
        register_smithproxy_cli2_commands(cli, cli_id());
    };
#ifdef USE_PAM
    if (!admin_group.empty()) {
        options.authenticate = [admin_group](std::string_view username, std::string_view password) {
            const std::string user(username), pass(password);
            if (!sx::auth::pam_auth_user_pass(user.c_str(), pass.c_str())) return -2;
            return sx::auth::unix_is_group_member(user.c_str(), admin_group.c_str()) ? 0 : -1;
        };
        options.privilege_after_auth = options.enable_password.empty();
    }
#endif
    libcli2_socket_loop(transport, std::move(options));

    Log::get()->remote_targets().remove_if([client_socket](const auto& entry) { return entry.first == client_socket; });
    Log::get()->target_profiles().erase(client_socket);
}

} // namespace

std::string cli_id() {
    std::ostringstream value;
    value << "cli-" << std::this_thread::get_id();
    return value.str();
}

void cli_loop(unsigned short port) {
    static auto log = logan::create("service");
    sockaddr_in address{};
    int reuse = 1;
    const int server = socle::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        _err("cli main thread - cannot create listener: %s", string_error().c_str());
        return;
    }
    if (socle::setsockopt(server, SOL_SOCKET, SO_REUSEADDR,
                          &reuse, sizeof(reuse)) != 0) {
        _err("cli main thread - cannot configure listener: %s", string_error().c_str());
        close(server);
        return;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    while (socle::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (SmithProxy::instance().terminate_flag) { close(server); return; }
        _err("cli main thread - cannot bind %d port: %s", port, string_error().c_str());
        if(errno != EADDRINUSE) {
            close(server);
            return;
        }
        sleep(1);
    }
    if (socle::listen(server, 50) != 0) {
        _err("cli main thread - cannot listen on port %d: %s", port, string_error().c_str());
        close(server);
        return;
    }
    epoll poller;
    if (poller.init() < 0) { _err("cli main thread: Can't initialize epoll"); close(server); return; }
    if (!poller.add(server, EPOLLIN)) {
        _err("cli main thread: Can't monitor listener");
        close(server);
        return;
    }
    std::vector<sx::cli::client_task> clients;
    while (!SmithProxy::instance().terminate_flag) {
        sx::cli::reap_finished_client_tasks(clients);
        if (poller.wait(1000) <= 0) continue;
        sockaddr_storage peer{};
        socklen_t length = sizeof(peer);
        const int client = accept4(server, reinterpret_cast<sockaddr*>(&peer), &length,
                                   SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (client >= 0) {
            auto finished = std::make_shared<std::atomic_bool>(false);
            clients.push_back({
                std::thread([client, finished] {
                    try {
                        client_thread(client);
                    } catch(std::exception const& error) {
                        _err("CLI client thread failed: %s", error.what());
                    } catch(...) {
                        _err("CLI client thread failed with an unknown exception");
                    }
                    finished->store(true, std::memory_order_release);
                }),
                std::move(finished),
            });
        }
    }
    close(server);
    for (auto& client : clients) if (client.worker.joinable()) client.worker.join();
}
