#pragma once

#include <ext/libcli2/cli.hpp>

#include <functional>
#include <string>

void register_smithproxy_cli2_commands(libcli2::Cli& cli, std::string subscriber_id = {},
                                       std::function<void()> refresh_prompt = {});
