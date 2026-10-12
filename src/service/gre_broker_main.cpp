#include <service/gre_broker.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>

#include <arpa/inet.h>

namespace {

void usage(const char* program) {
    std::cerr << "Usage: " << program
              << " --comm-gre <path> --destination <address>"
                 " [--ttl <1-255>] [--bind-interface <name>]\n";
}

} // namespace

int main(int argc, char** argv) {
    constexpr int option_destination = 1000;
    constexpr int option_ttl = 1001;
    constexpr int option_bind_interface = 1002;
    static option options[] = {
        {"comm-gre", required_argument, nullptr, 's'},
        {"destination", required_argument, nullptr, option_destination},
        {"ttl", required_argument, nullptr, option_ttl},
        {"bind-interface", required_argument, nullptr, option_bind_interface},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };

    std::string path;
    sx::comm::gre::Profile profile;
    for(;;) {
        const int value = ::getopt_long(argc, argv, "hs:", options, nullptr);
        if(value < 0) break;
        switch(value) {
            case 's': path = optarg; break;
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            case option_destination: profile.destination = optarg; break;
            case option_ttl: {
                char* end = nullptr;
                const long ttl = std::strtol(optarg, &end, 10);
                if(end == optarg || *end != '\0' || ttl < 1 || ttl > 255) {
                    std::cerr << "Invalid GRE TTL\n";
                    return EXIT_FAILURE;
                }
                profile.ttl = static_cast<int>(ttl);
                break;
            }
            case option_bind_interface: profile.bind_interface = optarg; break;
            default: usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if(path.empty() || profile.destination.empty() || optind != argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    in_addr address4{};
    in6_addr address6{};
    if(::inet_pton(AF_INET, profile.destination.c_str(), &address4) == 1) {
        profile.family = AF_INET;
    } else if(::inet_pton(AF_INET6, profile.destination.c_str(), &address6) == 1) {
        profile.family = AF_INET6;
    } else {
        std::cerr << "Destination must be an IPv4 or IPv6 address\n";
        return EXIT_FAILURE;
    }

    if(sx::comm::gre::run_standalone_broker(path, std::move(profile)) != 0) {
        std::cerr << "GRE broker failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
