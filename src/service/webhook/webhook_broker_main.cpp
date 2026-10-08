#include <service/webhook/webhook_broker.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>

namespace {
void usage(const char* program) {
    std::cerr << "Usage: " << program
              << " --comm-webhook <path> --destination <host> --port <port>"
                 " [--bind-interface <name>] [--max-sessions <count>]"
                 " [--connect-timeout-ms <milliseconds>]"
                 " [--idle-timeout-ms <milliseconds>]\n";
}

bool parse_positive(const char* value, long maximum, long& output) {
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    if(errno != 0 || end == value || *end != '\0' || parsed < 1 || parsed > maximum)
        return false;
    output = parsed;
    return true;
}
}

int main(int argc, char** argv) {
    constexpr int option_destination = 1000;
    constexpr int option_port = 1001;
    constexpr int option_interface = 1002;
    constexpr int option_max_sessions = 1003;
    constexpr int option_timeout = 1004;
    constexpr int option_idle_timeout = 1005;
    static option options[] = {
        {"comm-webhook", required_argument, nullptr, 's'},
        {"destination", required_argument, nullptr, option_destination},
        {"port", required_argument, nullptr, option_port},
        {"bind-interface", required_argument, nullptr, option_interface},
        {"max-sessions", required_argument, nullptr, option_max_sessions},
        {"connect-timeout-ms", required_argument, nullptr, option_timeout},
        {"idle-timeout-ms", required_argument, nullptr, option_idle_timeout},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    sx::comm::webhook::BrokerConfig config;
    for(;;) {
        const int value = ::getopt_long(argc, argv, "hs:", options, nullptr);
        if(value < 0) break;
        long parsed = 0;
        switch(value) {
            case 's': config.comm_path = optarg; break;
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            case option_destination: config.destination_host = optarg; break;
            case option_interface: config.bind_interface = optarg; break;
            case option_port:
                if(!parse_positive(optarg, 65535, parsed)) {
                    std::cerr << "Invalid destination port\n"; return EXIT_FAILURE;
                }
                config.destination_port = static_cast<std::uint16_t>(parsed);
                break;
            case option_max_sessions:
                if(!parse_positive(optarg, 1000000, parsed)) {
                    std::cerr << "Invalid maximum session count\n"; return EXIT_FAILURE;
                }
                config.max_active_sessions = static_cast<std::size_t>(parsed);
                break;
            case option_timeout:
                if(!parse_positive(optarg, 3600000, parsed)) {
                    std::cerr << "Invalid connect timeout\n"; return EXIT_FAILURE;
                }
                config.connect_timeout_ms = static_cast<int>(parsed);
                break;
            case option_idle_timeout:
                if(!parse_positive(optarg, 86400000, parsed)) {
                    std::cerr << "Invalid idle timeout\n"; return EXIT_FAILURE;
                }
                config.idle_timeout_ms = static_cast<int>(parsed);
                break;
            default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if(config.comm_path.empty() || config.destination_host.empty()
       || config.destination_port == 0 || optind != argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    sx::comm::webhook::BrokerServer server(std::move(config));
    if(server.run() != 0) {
        std::cerr << "Webhook broker failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
