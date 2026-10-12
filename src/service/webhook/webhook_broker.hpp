#pragma once

#include <string>

#include <service/stream/tcp_relay.hpp>

namespace sx::comm::webhook {

using BrokerConfig = sx::comm::stream::TcpRelayConfig;
using BrokerServer = sx::comm::stream::TcpRelayServer;
using Stats = sx::comm::stream::TcpRelayStats;

int configure_transport(const std::string& path);
void clear_transport() noexcept;
bool enabled() noexcept;
std::string transport_path();

} // namespace sx::comm::webhook
