#pragma once

#include "config_cli2.hpp"

#include <ext/libcli2/cli.hpp>
#include <ext/libcli2/fd_transport.hpp>

#include <functional>
#include <string>
#include <string_view>

struct Libcli2SocketOptions {
    std::string banner;
    std::string enable_password;
    ConfigCli2Access config_access;
    std::function<void(libcli2::Cli&)> register_commands;
    std::function<std::string(const libcli2::Context&)> prompt;
    std::function<int(std::string_view, std::string_view)> authenticate;
    std::function<int(libcli2::Context&)> regular;
    bool privilege_after_auth = false;
};

// Returns zero on a normal disconnect. A regular callback may return 1 to close
// the session; command handlers use the same value for an explicit quit.
int libcli2_socket_loop(libcli2::FdTransport& transport, Libcli2SocketOptions options);
