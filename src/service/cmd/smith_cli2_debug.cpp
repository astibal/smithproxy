#include "smith_cli2_debug.hpp"

#include "cli_debug_state.hpp"

#include <inspect/dns.hpp>
#include <inspect/dnsinspector.hpp>
#include <policy/authfactory.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/socks5/socksproxy.hpp>
#include <service/cfgapi/cfgapi.hpp>

#include <socle.hpp>
#include <sslcertstore.hpp>

#include <charconv>
#include <sstream>

namespace {

bool privileged_exec(const libcli2::Context& context) { return context.privilege >= 15 && context.mode == "0"; }

bool level(std::string_view text, int& result) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && result >= 0 && result <= 10;
}

libcli2::Command& debug_command(libcli2::Cli& cli, std::string_view name, std::string_view help) {
    return cli.command(std::string("debug ") + std::string(name))
        .reset_definition()
        .help(std::string(help))
        .available_if(privileged_exec)
        .argument({"arguments", "Optional level, reset, or command arguments", false, true});
}

void print_log_levels(libcli2::Context& context) {
    std::ostringstream output;
    const auto profile = Log::get()->target_profiles().find(static_cast<std::uint64_t>(context.io_handle));
    if (profile != Log::get()->target_profiles().end() && profile->second)
        output << "THIS cli logging level set to: " << profile->second->level_.level() << '\n';
    output << "Internal logging level set to: " << Log::get()->level().level() << '\n';
    for (const auto& [target, mutex] : Log::get()->remote_targets()) {
        const auto found = Log::get()->target_profiles().find(static_cast<std::uint64_t>(target));
        if (found != Log::get()->target_profiles().end() && found->second)
            output << "Logging level for remote: " << Log::get()->target_name(target) << ": "
                   << found->second->level_.level() << '\n';
    }
    context.print(output.str());
}

template <typename Show, typename Set, typename Reset>
int level_command(libcli2::Context& context, const libcli2::Invocation& invocation,
                  Show show, Set set, Reset reset) {
    if (invocation.arguments.empty()) {
        context.print(show());
        context.print(CliDebugState::get().debug_levels);
        return 0;
    }
    if (invocation.arguments.front() == "reset") {
        reset();
        return 0;
    }
    int value = -1;
    if (!level(invocation.arguments.front(), value)) {
        context.print("logging level must be 0..10 or reset");
        return -1;
    }
    set(value);
    return 0;
}

std::string proxy_levels() {
    std::ostringstream out;
    out << "baseProxy debug level: " << baseProxy::log_level().level() << '\n';
    out << "epoll debug level: " << epoll::log_level.level() << '\n';
    out << "MitmMasterProxy debug level: " << MitmMasterProxy::log_level().level() << '\n';
    out << "MitmHostCX debug level: " << MitmHostCX::log_level().level() << '\n';
    out << "MitmProxy debug level: " << MitmProxy::log_level().level() << '\n';
    out << "SocksProxy debug level: " << SocksProxy::log_level().level();
    return out.str();
}

}  // namespace

void register_smithproxy_cli2_debug(libcli2::Cli& cli) {
    debug_command(cli, "term", "Set logging level for this terminal")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            auto found = Log::get()->target_profiles().find(static_cast<std::uint64_t>(context.io_handle));
            if (found == Log::get()->target_profiles().end() || !found->second) return -1;
            if (invocation.arguments.empty()) { print_log_levels(context); return 0; }
            if (invocation.arguments.front() == "reset") found->second->level_ = NON;
            else {
                int value = -1;
                if (!level(invocation.arguments.front(), value)) return -1;
                found->second->level_.level(value);
            }
            context.print("this terminal logging level changed to " + std::to_string(found->second->level_.level()));
            return 0;
        });

    debug_command(cli, "level", "Set internal logging level")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            if (invocation.arguments.empty()) { print_log_levels(context); return 0; }
            if (invocation.arguments.front() == "reset") Log::get()->level(CfgFactory::get()->internal_init_level);
            else {
                int value = -1;
                if (!level(invocation.arguments.front(), value)) return -1;
                Log::get()->level(loglevel(value, 0));
            }
            context.print("internal logging level changed to " + std::to_string(Log::get()->level().level()));
            return 0;
        });

    debug_command(cli, "file", "Set standard log file level")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            if (invocation.arguments.empty()) { print_log_levels(context); return 0; }
            int value = static_cast<int>(CfgFactory::get()->internal_init_level.level());
            if (invocation.arguments.front() != "reset" && !level(invocation.arguments.front(), value)) return -1;
            for (const auto& [target, mutex] : Log::get()->targets()) {
                const auto key = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(target.get()));
                if (Log::get()->target_name(key) != CfgFactory::get()->log_file) continue;
                const auto found = Log::get()->target_profiles().find(key);
                if (found != Log::get()->target_profiles().end() && found->second) found->second->level_.level(value);
            }
            context.print("log file logging level changed to " + std::to_string(value));
            return 0;
        });

    debug_command(cli, "ssl", "Set SSL logging level")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            return level_command(context, invocation,
                [] { return "SSL debug level: " + std::to_string(SSLCom::log_level().level()) +
                            "\nSSL MitM debug level: " + std::to_string(SSLMitmCom::log_level().level()) +
                            "\nSSL CA debug level: " + std::to_string(SSLFactory::get_log().level()->level()); },
                [](int value) { SSLCom::log_level().level(value); SSLMitmCom::log_level().level(value); SSLFactory::get_log().level(loglevel(value)); },
                [] { SSLCom::log_level() = CliDebugState::get().orig_ssl_loglevel; SSLMitmCom::log_level() = CliDebugState::get().orig_sslmitm_loglevel; SSLFactory::get_log().level(CliDebugState::get().orig_sslca_loglevel); });
        });

    debug_command(cli, "dns", "Set DNS logging level")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            return level_command(context, invocation,
                [] { return "DNS Inspector debug level: " + std::to_string(DNS_Inspector::log_level().level()) +
                            "\nDNS Packet debug level: " + std::to_string(DNS_Packet::log_level().level()); },
                [](int value) { DNS_Inspector::log_level().level(value); DNS_Packet::log_level().level(value); },
                [] { DNS_Inspector::log_level() = CliDebugState::get().orig_dns_insp_loglevel; DNS_Packet::log_level() = CliDebugState::get().orig_dns_packet_loglevel; });
        });

    debug_command(cli, "auth", "Set authentication logging level")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            return level_command(context, invocation,
                [] { return "Auth debug level: " + std::to_string(AuthFactory::log_level().level()); },
                [](int value) { AuthFactory::log_level().level(value); },
                [] { AuthFactory::log_level() = CliDebugState::get().orig_auth_loglevel; });
        });

    debug_command(cli, "proxy", "Set proxy logging levels")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            return level_command(context, invocation, proxy_levels,
                [](int value) { baseProxy::log_level().level(value); epoll::log_level.level(value); MitmMasterProxy::log_level().level(value); MitmHostCX::log_level().level(value); MitmProxy::log_level().level(value); SocksProxy::log_level().level(value); },
                [] { baseProxy::log_level() = CliDebugState::get().orig_baseproxy_loglevel; epoll::log_level = CliDebugState::get().orig_epoll_loglevel; MitmMasterProxy::log_level() = CliDebugState::get().orig_mitmmasterproxy_loglevel; MitmHostCX::log_level() = CliDebugState::get().orig_mitmhostcx_loglevel; MitmProxy::log_level() = CliDebugState::get().orig_mitmproxy_loglevel; SocksProxy::log_level() = CliDebugState::get().orig_socksproxy_loglevel; });
        });

    cli.command("debug show").reset_definition().help("Show debug settings").available_if(privileged_exec)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            std::ostringstream output;
            output << proxy_levels() << "\n\nlogan light loggers\n";
            for (const auto& [topic, value] : logan::get()->topic_db_)
                output << "    [" << topic << "] => level " << value->level() << " flag: " << value->topic() << '\n';
            context.print(output.str());
            return 0;
        });

    debug_command(cli, "set", "Change lightweight logger settings")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            auto logger = logan::get();
            if (invocation.arguments.empty()) {
                std::ostringstream output;
                output << "Usage: debug set <topic|all|cli|filter> [level|value]\nVariable list:\n";
                for (const auto& [topic, value] : logger->topic_db_) output << topic << '\n';
                context.print(output.str());
                return 0;
            }
            const auto& name = invocation.arguments[0];
            if (name == "cli") {
                if (invocation.arguments.size() > 1) { int value = 0; if (!level(invocation.arguments[1], value)) return -1; CliDebugState::get().cli_debug_flag = value > 0; }
                context.print(std::string("cli debug now ") + (CliDebugState::get().cli_debug_flag ? "ON" : "OFF"));
                return 0;
            }
            if (name == "filter") {
                const std::string value = invocation.arguments.size() > 1 ? invocation.arguments[1] : "";
                logan_lite::context_filter.active(false); logan_lite::context_filter.set(value); logan_lite::context_filter.active(!value.empty());
                context.print(value.empty() ? "Logging context filter deactivated" : "Logging context filter set to: '" + value + "'");
                return 0;
            }
            int value = -1;
            if (invocation.arguments.size() > 1 && !level(invocation.arguments[1], value)) return -1;
            if (name == "all" || name == "*") {
                for (const auto& [topic, entry] : logger->topic_db_) if (value >= 0) entry->level(value);
                context.print(value >= 0 ? "all lightweight logger levels changed" : "all lightweight logger levels queried");
                return 0;
            }
            const auto found = logger->topic_db_.find(name);
            if (found == logger->topic_db_.end()) { context.print("variable not recognized"); return -1; }
            if (value >= 0) found->second->level(value);
            context.print("debug level: " + name + ": " + std::to_string(found->second->level()));
            return 0;
        });
}
