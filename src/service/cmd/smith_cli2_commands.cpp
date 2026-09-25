#include "smith_cli2_commands.hpp"
#include "smith_cli2_debug.hpp"
#include "smith_cli2_test.hpp"
#include "config_cli2.hpp"
#include "diag/diag_cmds.hpp"

#include <service/cfgapi/cfgapi.hpp>

#include <inspect/kb/kb.hpp>
#include <log/logger.hpp>
#include <proxy/mitmproxy.hpp>
#include <service/core/smithproxy.hpp>
#include <traflog/pcaplog.hpp>

#include <display.hpp>
#include <timeops.hpp>
#include <socle.hpp>

#include <main.hpp>
#include "smithproxy_version.h"
#include "socle_version.h"

#include <libconfig.h++>

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>

namespace {

bool privileged(const libcli2::Context& context) { return context.privilege >= 15; }
bool exec_mode(const libcli2::Context& context) { return context.mode == "0"; }
bool privileged_exec(const libcli2::Context& context) { return privileged(context) && exec_mode(context); }

std::string status_text() {
    std::ostringstream output;
    output << "Version: " << SMITH_VERSION << (SMITH_DEVEL ? " (dev)" : "") << '\n';
    output << "Socle: " << SOCLE_VERSION << (SOCLE_DEVEL ? " (dev)" : "") << '\n';
#if (SMITH_DEVEL > 0) || (SOCLE_DEVEL > 0)
    output << "Smithproxy source info: " << SX_GIT_VERSION << '\n';
    output << "                branch: " << SX_GIT_BRANCH << " commit: " << SX_GIT_COMMIT_HASH << '\n';
    output << " Socle lib source info: " << SOCLE_GIT_VERSION << '\n';
    output << "                branch: " << SOCLE_GIT_BRANCH << " commit: " << SOCLE_GIT_COMMIT_HASH << '\n';
#endif
    output << "Built with: ";
#ifndef BUILD_RELEASE
    output << "DEBUG ";
#endif
#ifdef USE_UNWIND
    output << "UNWIND ";
#endif
#ifdef MEMPOOL_ALL
    output << "MEMPOOL_ALL ";
#endif
#ifdef MEMPOOL_DEBUG
    output << "MEMPOOL_DEBUG ";
#endif
#ifdef USE_PYTHON
    output << "PYTHON ";
#endif
#ifdef USE_LMHPP
    output << "LMHPP ";
#endif
#ifdef USE_EXPERIMENT
    output << "EXPERIMENTAL ";
#endif
    output << "\n\n";

    const auto proxy_type = [](const auto& proxies) { return proxies.empty() ? "none" : proxies[0]->sq_type_str(); };
    const auto multiplier = [](const auto& proxies) { return proxies.empty() ? -1 : proxies[0]->core_multiplier(); };
    const auto tasks = [](const auto& proxies) { return proxies.empty() ? 0 : proxies[0]->task_count(); };
    auto& smith = SmithProxy::instance();
    output << "CPU cores detected: " << std::thread::hardware_concurrency()
           << ", acc multi: " << multiplier(smith.plain_proxies)
           << " recv multi: " << multiplier(smith.udp_proxies) << '\n';
    output << "Acceptor hinting: tcp:" << proxy_type(smith.plain_proxies)
           << ", tls:" << proxy_type(smith.ssl_proxies)
           << ", udp:" << proxy_type(smith.udp_proxies)
           << ", dtls:" << proxy_type(smith.dtls_proxies) << '\n';

    const auto acceptors = [&](std::string_view title, std::string_view protocol, const auto& proxies) {
        output << "\n" << title << ":\n  " << protocol << ": " << proxies.size()
               << " workers: " << proxies.size() * static_cast<std::size_t>(tasks(proxies)) << '\n';
    };
    if (CfgFactory::get()->accept_tproxy) {
        output << "\nTproxy acceptors:\n";
        output << "  TCP: " << smith.plain_proxies.size() << " workers: " << smith.plain_proxies.size() * tasks(smith.plain_proxies) << '\n';
        output << "  UDP: " << smith.udp_proxies.size() << " workers: " << smith.udp_proxies.size() * tasks(smith.udp_proxies) << '\n';
        output << "  TLS: " << smith.ssl_proxies.size() << " workers: " << smith.ssl_proxies.size() * tasks(smith.ssl_proxies) << '\n';
        output << "  DTLS: " << smith.dtls_proxies.size() << " workers: " << smith.dtls_proxies.size() * tasks(smith.dtls_proxies) << '\n';
    }
    if (CfgFactory::get()->accept_redirect) {
        output << "\nRedirect acceptors:\n";
        output << "  TCP: " << smith.redir_plain_proxies.size() << " workers: " << smith.redir_plain_proxies.size() * tasks(smith.redir_plain_proxies) << '\n';
        output << "  UDP: " << smith.redir_udp_proxies.size() << " workers: " << smith.redir_udp_proxies.size() * tasks(smith.redir_udp_proxies) << '\n';
        output << "  TLS: " << smith.redir_ssl_proxies.size() << " workers: " << smith.redir_ssl_proxies.size() * tasks(smith.redir_ssl_proxies) << '\n';
    } else {
        output << "\nRedirect acceptors: disabled\n";
    }
    if (CfgFactory::get()->accept_socks) acceptors("Socks acceptors", "TCP", smith.socks_proxies);
    else output << "\nSOCKS acceptors: disabled\n";

    output << "\nUptime: " << uptime_string(time(nullptr) - smith.ts_sys_started) << '\n';
    const unsigned long upload = MitmProxy::total_mtr_up().get();
    const unsigned long download = MitmProxy::total_mtr_down().get();
    output << "Performance: upload " << number_suffixed(upload * 8) << "bps, download "
           << number_suffixed(download * 8) << "bps in last 60 seconds\n";
    const unsigned long total = MitmProxy::total_mtr_up().total() + MitmProxy::total_mtr_down().total();
    output << "Transferred: " << number_suffixed(total) << " bytes\n";
    output << "Total sessions: " << MitmProxy::total_sessions().load() << '\n';
    if (CfgFactory::board()->version_saved() < CfgFactory::board()->version_current())
        output << "\n*** Configuration changes NOT saved ***\n";
    return output.str();
}

std::string render(libconfig::Config& config) {
    char* data = nullptr;
    std::size_t size = 0;
    FILE* stream = ::open_memstream(&data, &size);
    if (!stream) return "error: config print failed";
    config.write(stream);
    if (::fclose(stream) != 0) {
        std::free(data);
        return "error: config print failed";
    }
    std::string result(data, size);
    std::free(data);
    return result;
}

std::string render_full_config() {
    std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
    return render(CfgFactory::cfg_obj());
}

std::string render_current_config(std::string_view path) {
    if (path.empty()) return render_full_config();
    std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
    try {
        auto& source = CfgFactory::cfg_obj().lookup(std::string(path));
        libconfig::Setting* container = &source;
        int index = -1;
        std::string label = source.getName() ? source.getName() : "current";

        const auto marker = path.rfind(".[");
        if (!source.getName() && marker != std::string_view::npos && path.back() == ']') {
            const auto number = path.substr(marker + 2, path.size() - marker - 3);
            const auto parsed = std::from_chars(number.data(), number.data() + number.size(), index);
            if (parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size()) index = -1;
            container = &CfgFactory::cfg_obj().lookup(std::string(path.substr(0, marker)));
            if (container->getName()) label = container->getName();
        }

        libconfig::Config copy;
#if LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7
        copy.setOptions(libconfig::Setting::OptionOpenBraceOnSeparateLine);
#else
        copy.setOptions(libconfig::Config::OptionOpenBraceOnSeparateLine);
#endif
        auto& target = copy.getRoot().add(label.c_str(), container->getType());
        CfgFactory::cfg_clone_setting(target, *container, index);
        return render(copy);
    } catch (const libconfig::SettingException&) {
        return "current configuration section no longer exists";
    }
}

std::string render_section(std::string_view name, int index = -1) {
    std::scoped_lock<std::recursive_mutex> lock(CfgFactory::lock());
    const std::string section_name(name);
    if (!CfgFactory::cfg_root().exists(section_name.c_str()))
        return "'" + section_name + "' config section doesn't exist";

    auto& source = CfgFactory::cfg_root().lookup(section_name.c_str());
    if (index >= 0 && (!source.isAggregate() || index >= source.getLength())) return "policy index is out of range";

    libconfig::Config copy;
#if LIBCONFIGXX_VER_MAJOR >= 1 && LIBCONFIGXX_VER_MINOR < 7
    copy.setOptions(libconfig::Setting::OptionOpenBraceOnSeparateLine);
#else
    copy.setOptions(libconfig::Config::OptionOpenBraceOnSeparateLine);
#endif
    auto& target = copy.getRoot().add(source.getName(), source.getType());
    CfgFactory::cfg_clone_setting(target, source, index);
    return render(copy);
}

void section_command(libcli2::Cli& cli, std::string_view name, std::string_view help) {
    cli.command(std::string("show config ") + std::string(name))
        .reset_definition()
        .help(std::string(help))
        .handler([section = std::string(name)](libcli2::Context& context, const libcli2::Invocation&) {
            context.print(render_section(section));
            return 0;
        });
}

}  // namespace

void register_smithproxy_cli2_commands(libcli2::Cli& cli, std::string subscriber_id,
                                       std::function<void()> refresh_prompt) {
    register_smithproxy_cli2_debug(cli);
    register_smithproxy_cli2_test(cli);
    register_diags(cli);
    const auto show_status = [](libcli2::Context& context, const libcli2::Invocation&) {
        if (context.mode != "0") {
            const auto* config = static_cast<const ConfigCli2Session*>(context.user_data);
            context.print(render_current_config(config ? config->path() : std::string{}));
        } else {
            context.print(status_text());
        }
        return 0;
    };
    cli.command("show").reset_definition().help("Show basic information").handler(show_status);
    cli.command("show status")
        .reset_definition()
        .help("Show Smithproxy status")
        .available_if(exec_mode)
        .handler(show_status);

    cli.command("show config full")
        .reset_definition()
        .help("Show complete Smithproxy configuration")
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            context.print(render_full_config());
            return 0;
        });

    cli.command("show config policy")
        .reset_definition()
        .help("Show policy configuration, optionally one numeric index")
        .argument({"index", "Optional policy index", false, false, {},
                   [](std::string_view value) {
                       int index = -1;
                       const auto parsed = std::from_chars(value.data(), value.data() + value.size(), index);
                       return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && index >= 0;
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            int index = -1;
            if (!invocation.arguments.empty()) {
                const auto& value = invocation.arguments.front();
                const auto parsed = std::from_chars(value.data(), value.data() + value.size(), index);
                if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || index < 0) return -1;
            }
            context.print(render_section("policy", index));
            return 0;
        });

    cli.command("show config objects")
        .reset_definition()
        .help("Show all protocol, port and address objects")
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            context.print(render_section("proto_objects"));
            context.print(render_section("port_objects"));
            context.print(render_section("address_objects"));
            return 0;
        });

    section_command(cli, "settings", "Show settings configuration");
    section_command(cli, "proto_objects", "Show protocol objects");
    section_command(cli, "port_objects", "Show port objects");
    section_command(cli, "address_objects", "Show address objects");
    section_command(cli, "detection_profiles", "Show detection profiles");
    section_command(cli, "content_profiles", "Show content profiles");
    section_command(cli, "tls_ca", "Show TLS certificate authorities");
    section_command(cli, "tls_profiles", "Show TLS profiles");
    section_command(cli, "alg_dns_profiles", "Show DNS ALG profiles");
    section_command(cli, "auth_profiles", "Show authentication profiles");
    section_command(cli, "starttls_signatures", "Show STARTTLS signatures");
    section_command(cli, "detection_signatures", "Show detection signatures");
    section_command(cli, "routing", "Show routing configuration");
    section_command(cli, "captures", "Show capture configuration");
#ifdef USE_EXPERIMENT
    section_command(cli, "experiment", "Show experimental configuration");
#endif

    cli.command("show event list")
        .reset_definition()
        .help("Show event list")
        .available_if(exec_mode)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            std::ostringstream output;
            auto& events = Log::get()->events();
            const auto lock = std::scoped_lock(events.events_lock());
            for (const auto& [id, event] : events.entries()) {
                const bool has_detail = events.event_details().find(id) != events.event_details().end();
                output << (has_detail ? "* " : "  ") << id << ": " << event << '\n';
            }
            context.print(output.str());
            return 0;
        });

    cli.command("show event detail")
        .reset_definition()
        .help("Show details for one event")
        .available_if(privileged_exec)
        .argument({"id", "Event identifier", true, false, {}, [](std::string_view value) {
                       unsigned long long id = 0;
                       const auto parsed = std::from_chars(value.data(), value.data() + value.size(), id);
                       return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && id > 0;
                   }})
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            unsigned long long id = 0;
            const auto& value = invocation.arguments.front();
            std::from_chars(value.data(), value.data() + value.size(), id);
            auto& events = Log::get()->events();
            const auto lock = std::scoped_lock(events.events_lock());
            const auto found = events.event_details().find(id);
            context.print(found == events.event_details().end()
                              ? "no details for this event id " + std::to_string(id)
                              : found->second);
            return 0;
        });

    cli.command("execute events clear")
        .reset_definition()
        .help("Clear event ring buffer")
        .available_if(privileged)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            Log::get()->events().clear();
            Log::get()->events().insert(CRI, "events cleared by admin");
            context.print("Events cleared");
            return 0;
        });

    cli.command("execute kb print")
        .reset_definition()
        .help("Print all knowledgebase entries")
        .available_if(privileged)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            std::string dump;
            {
                auto kb = sx::KB::get();
                const auto lock = std::scoped_lock(sx::KB::lock());
                dump = kb->to_json().dump(4);
            }
            context.print("Knowledgebase dump:");
            context.print(dump);
            return 0;
        });

    cli.command("execute kb clear")
        .reset_definition()
        .help("Clear all knowledgebase entries")
        .available_if(privileged)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            std::size_t count = 0;
            {
                auto kb = sx::KB::get();
                const auto lock = std::scoped_lock(sx::KB::lock());
                count = kb->elements.size();
                kb->elements.clear();
            }
            context.print("Knowledgebase cleared " + std::to_string(count) + " entries");
            return 0;
        });

    cli.command("execute pcap rollover")
        .reset_definition()
        .help("Rollover PCAP file now")
        .available_if(privileged)
        .handler([](libcli2::Context&, const libcli2::Invocation&) {
            socle::traflog::PcapLog::single_instance().rotate_now = true;
            return 0;
        });

    cli.command("save config")
        .reset_definition()
        .help("Save running configuration")
        .available_if(privileged)
        .argument({"force", "Save even when the input configuration contained errors", false, false, {},
                   [](std::string_view value) { return value == "force"; }})
        .handler([subscriber_id, refresh_prompt](libcli2::Context& context, const libcli2::Invocation& invocation) {
            const bool force = !invocation.arguments.empty();
            if (CfgFactory::LOAD_ERRORS && !force) {
                context.print("Warning: configuration loaded only partially; fix it and execute reload, "
                              "or use 'save config force' to discard invalid parts.");
                return 0;
            }
            const int result = CfgFactory::get()->save_config();
            if (result < 0) {
                context.print(std::string(force ? "enforced: " : "") + "error writing config file!");
                return -1;
            }
            CfgFactory::board()->save(subscriber_id);
            CfgFactory::board()->ack_saved(subscriber_id);
            if (refresh_prompt) refresh_prompt();
            context.print(std::string(force ? "enforced: " : "") + "config saved successfully.");
            return 0;
        });

    cli.command("execute reload")
        .reset_definition()
        .help("Reload configuration file")
        .available_if(privileged)
        .handler([subscriber_id, refresh_prompt](libcli2::Context& context, const libcli2::Invocation&) {
            const bool loaded = SmithProxy::instance().load_config(CfgFactory::get()->config_file, true);
            CfgFactory::board()->rollback(subscriber_id);
            if (!loaded) {
                context.print("Configuration file reload FAILED");
                return -1;
            }
            CfgFactory::board()->ack_current(subscriber_id);
            if (refresh_prompt) refresh_prompt();
            context.print(std::string("Configuration file reloaded") +
                          (CfgFactory::LOAD_ERRORS ? " (with some errors)" : ""));
            return 0;
        });

    cli.command("execute shutdown")
        .reset_definition()
        .help("Terminate this Smithproxy process gracefully")
        .available_if(privileged)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            context.print("\n!!! terminating smithproxy !!!");
            SmithProxy::instance().terminate_flag = true;
            return 0;
        });
}
