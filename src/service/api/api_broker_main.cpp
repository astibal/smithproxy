#include <service/cli/cli_broker.hpp>

#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>

namespace {
void usage(const char* program) {
    std::cerr << "Usage: " << program
              << " --comm-api <path> [--listen-address <IPv4>] [--listen-port <port>]"
                 " [--bind-interface <name>] [--allow-ip <IPv4>]\n";
}
}

int main(int argc, char** argv) {
    constexpr int option_address = 1000;
    constexpr int option_port = 1001;
    constexpr int option_allow_ip = 1002;
    constexpr int option_bind_interface = 1003;
    static option options[] = {
        {"comm-api", required_argument, nullptr, 's'},
        {"listen-address", required_argument, nullptr, option_address},
        {"listen-port", required_argument, nullptr, option_port},
        {"allow-ip", required_argument, nullptr, option_allow_ip},
        {"bind-interface", required_argument, nullptr, option_bind_interface},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    sx::comm::stream::BrokerConfig config;
    config.listen_port = 55555;
    config.allowed_ips.clear();
    for(;;) {
        const int value = ::getopt_long(argc, argv, "hs:", options, nullptr);
        if(value < 0) break;
        switch(value) {
            case 's': config.comm_path = optarg; break;
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            case option_address: config.listen_address = optarg; break;
            case option_allow_ip: config.allowed_ips.emplace_back(optarg); break;
            case option_bind_interface: config.bind_interface = optarg; break;
            case option_port: {
                char* end = nullptr;
                const long port = std::strtol(optarg, &end, 10);
                if(end == optarg || *end != '\0' || port < 1 || port > 65535) {
                    std::cerr << "Invalid listen port\n"; return EXIT_FAILURE;
                }
                config.listen_port = static_cast<std::uint16_t>(port);
                break;
            }
            default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if(config.allowed_ips.empty()) config.allowed_ips.emplace_back("*");
    if(config.comm_path.empty() || optind != argc) { usage(argv[0]); return EXIT_FAILURE; }
    sx::comm::stream::BrokerServer server(std::move(config));
    if(server.run() != 0) {
        std::cerr << "API broker failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
