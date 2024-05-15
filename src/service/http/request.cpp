#include <service/tpool.hpp>
#include <service/core/smithproxy.hpp>
#include <optional>
#include <curl/curl.h>
#include <string>
#include <iostream>
#include <service/http/request.hpp>

namespace sx::http {

Request::Initializator sx::http::Request::curl_initializator;

expected_reply Request::make_reply(std::string url, long code, std::string reply) {
    sx::http::expected_reply_t r;
    r.ctrl = this;
    r.request = url;
    r.response.first = code;
    r.response.second = reply;

    return std::optional(r);
}

}