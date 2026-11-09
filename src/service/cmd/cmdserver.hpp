#pragma once

#include <string>

struct CliSessionMetadata {
    std::string authenticated_user;
    std::string source;
    std::string broker;
};

class CliSession {
public:
    explicit CliSession(int fd, CliSessionMetadata metadata = {});
    void run();

private:
    int fd_;
    CliSessionMetadata metadata_;
};

void cli_loop(int listener_fd);
std::string cli_id();
