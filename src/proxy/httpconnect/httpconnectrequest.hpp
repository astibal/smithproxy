#ifndef SMITHPROXY_HTTPCONNECTREQUEST_HPP
#define SMITHPROXY_HTTPCONNECTREQUEST_HPP

#include <optional>
#include <string>
#include <string_view>

struct HttpConnectRequest {
    std::string host;
    unsigned short port = 0;

    static std::optional<HttpConnectRequest> parse(std::string_view request_line);
};

#endif // SMITHPROXY_HTTPCONNECTREQUEST_HPP
