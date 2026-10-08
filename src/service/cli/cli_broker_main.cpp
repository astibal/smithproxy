#include <service/cli/cli_broker.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>

namespace {
void usage(const char* program) {
    std::cerr << "Usage: " << program
              << " --comm-cli <path> [--listen-address <IPv4>] [--listen-port <port>]\n";
}
}

int main(int argc, char** argv) {
    constexpr int option_address = 1000;
    constexpr int option_port = 1001;
    static option options[] = {
        {"comm-cli", required_argument, nullptr, 's'},
        {"listen-address", required_argument, nullptr, option_address},
        {"listen-port", required_argument, nullptr, option_port},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    sx::comm::cli::BrokerConfig config;
    for(;;) {
        const int value = ::getopt_long(argc, argv, "hs:", options, nullptr);
        if(value < 0) break;
        switch(value) {
            case 's': config.comm_path = optarg; break;
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            case option_address: config.listen_address = optarg; break;
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
    if(config.comm_path.empty() || optind != argc) { usage(argv[0]); return EXIT_FAILURE; }
    sx::comm::cli::CliBrokerServer server(std::move(config));
    if(server.run() != 0) {
        std::cerr << "CLI broker failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
