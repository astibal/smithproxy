#include "broker_client.hpp"
#include <iostream>

int main(int argc, char** argv) {
    if(argc != 3) {
        std::cerr << "Usage: smithproxy-auth-check <socket> <username> (password on stdin)\n";
        return 2;
    }
    try {
        std::string password;
        char byte;
        while(std::cin.get(byte) && byte != '\n') {
            if(password.size() == 1024) {
                return 2;
            }
            password.push_back(byte);
        }
        sx::auth::BrokerPapBackend backend(argv[1]);
        sx::auth::Result result;
        sx::auth::PapExchange exchange({}, {});
        exchange.verify(backend, argv[2], password, [&](sx::auth::Result value) {
            result = std::move(value);
        });
        if(result.status == sx::auth::Status::accepted) {
            std::cout << "accepted " << result.identity << '\n';
            for(const auto& group : result.groups) {
                std::cout << "group " << group << '\n';
            }
            return 0;
        }
        std::cout << (result.status == sx::auth::Status::rejected ? "rejected\n" : "unavailable\n");
        return 1;
    } catch(const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
