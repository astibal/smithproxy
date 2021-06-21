#ifndef DNSENGINE_HPP
#define DNSENGINE_HPP

#include <inspect/dns.hpp>

struct app_DNS : public ApplicationData {
    DNS_Request*  request = nullptr;
    DNS_Response* response = nullptr;

    TYPENAME_OVERRIDE("app_DNS")
};

#endif
