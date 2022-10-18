/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#ifndef HTTPD_HPP_
#define HTTPD_HPP_

#include <cstdlib>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <ext/json/json.hpp>
#include <main.hpp>
#include <common/display.hpp>

#include <openssl/rand.h>

namespace sx::webserver {


    template <typename T>
    struct TimedOptional {
        TimedOptional(T v, unsigned int in_seconds): value_(v), expired_at_(::time(nullptr) + in_seconds) {}
        explicit TimedOptional() : TimedOptional(T(), 3600) {};
        virtual ~TimedOptional() = default;

        void extend(uint32_t add) { expired_at_ = ::time(nullptr) + add; }
        bool expired() const { return (this->expired_at_ <= ::time(nullptr)); }
        std::optional<T> optional() {
            if(expired()) {
                return std::nullopt;
            }
            return value_;
        };
        std::optional<T> stored_optional() const {
            return value_;
        };

        time_t expired_at() const { return expired_at_; };

        bool operator==(TimedOptional<T> const &ref) {
            if(value_.has_value() and ref.has_value()) {
                return value_.value() == ref.value().value();
            }
            else if(not value_.has_value() and not ref.has_value()) {
                return true;
            }

            return false;
        }
        static T default_value() { return {}; }


    private:
        std::optional<T> value_ = std::nullopt;
        time_t expired_at_{0};
    };

    template<typename T>
    struct hash {
        std::size_t operator()(TimedOptional<T>& v) const {
            return std::hash<const char*>()(v.stored_optional().value_or(TimedOptional<T>::default_value() ).c_str());
        }
    };


    using named_var_t = std::unordered_map<std::string, TimedOptional<std::string>>;
    using sessions_t = std::unordered_map<std::string, named_var_t>;


struct HttpSessions {

    static inline std::mutex lock;
    static inline std::set<std::string> api_keys;
    static inline sessions_t access_keys;
    static inline uint32_t session_ttl = 3600;
    static inline bool extend_on_access = true;
    static inline bool loopback_only = true;
    static inline int api_port = 55555;
#ifdef USE_PAM
    static inline bool pam_login = true;
#endif

    enum class cookie_samesite { None, Lax, Strict };

    constexpr static const char* COOKIE_AUTH_TOKEN="__sx_api";
    static inline cookie_samesite COOKIE_SAMESITE = cookie_samesite::Strict;

    constexpr static const char* HEADER_CSRF_TOKEN="csrf_token";

    constexpr static const char* ATT_AUTH_TOKEN = "auth_token";
    constexpr static const char* ATT_CSRF_TOKEN = "csrf_token";

    static std::string table_value(std::string const& key, std::string const& varname, bool create=false) {
        auto lc_ = std::scoped_lock(lock);

        auto key_it = access_keys.find(key);
        if(create and key_it == access_keys.end()) {
            access_keys[key] = named_var_t(); key_it = access_keys.find(key);
        }

        if(key_it != access_keys.end()) {
            if(auto var_it = key_it->second.find(varname); var_it != key_it->second.end()) {

                auto& val = var_it->second;

                if(val.optional().has_value()) {

                    if (extend_on_access) {
                        // access element by reference
                        val.extend(session_ttl);
                    }

                    return val.optional().value();
                }
                else {
                    // erase empty var (invalidates iterator!)
                    key_it->second.erase(varname);
                    return {};
                }
            }
            else if(create) {
                return key_it->second[varname].optional().value_or("");
            }
        }

        return {};
    }

    static std::string generate_auth_token() {
        unsigned char rand_pool[16];
        RAND_bytes(rand_pool, 16);
        return hex_print(rand_pool, 16);
    }

    static std::string generate_csrf_token() {
        unsigned char rand_pool[16];
        RAND_bytes(rand_pool, 16);
        return hex_print(rand_pool, 16);
    }

    static bool validate_tokens(std::string const& auth_token, std::string const& csrf_token) {

        // don't report valid access if tokens are empty and there are none also in the database
        if(auth_token.empty() or csrf_token.empty()) return false;

        auto db_csrf_token = table_value(auth_token, "csrf_token");
        bool ret = ( csrf_token == db_csrf_token );

        if(not ret) {
            auto lc_ = std::scoped_lock(lock);
            //eventually erase this auth_token
            access_keys.erase(auth_token);
        }

        return ret;
    }
};

std::thread* create_httpd_thread(unsigned short port);

struct Http_JsonResponseParams : public lmh::ResponseParams {
    nlohmann::json response;
};

template <typename Callable>
class Http_JsonResponder : public lmh::DynamicController {
    std::string meth;
    std::string path;

    Callable responder;

    static inline const std::vector<std::pair<std::string, std::string>> json_response_headers  = {
            { "X-Vendor", "smithproxy " SMITH_VERSION },
            { "Content-Type", "application/json" },
            { "Access-Control-Allow-Origin", "*" },
            };

public:
    Http_JsonResponder(std::string m, std::string p, Callable r)
            : meth(std::move(m)), path(std::move(p)), responder(r) {};

    bool validPath(const char* arg_path, const char* arg_method) override {
        if(arg_path == path and arg_method == meth) return true;

        if(arg_method == meth) {
            std::string argp = arg_path;
            if(argp.find(path + "?") == 0) {
                return true;
            }
        }
        return false;
    }

    lmh::ResponseParams createResponse(struct MHD_Connection * connection,
            const char * url, const char * method, const char * upload_data,
            size_t * upload_data_size, void** ptr, std::stringstream& response) override {

        auto meth_str = std::string(meth);
        std::string request_data;

        auto* body = static_cast<lmh::ConnectionState*>(*ptr);

        if (not body) {
            if(meth_str == "POST") {
                lmh::ResponseParams ret;
                ret.response_code = MHD_YES;
                if(not *ptr) *ptr = new lmh::ConnectionState(*this);

                return ret;
            }
        }
        else if(*upload_data_size > 0) {
            std::string inc(upload_data, *upload_data_size);
            body->request_data += inc.c_str();
            *upload_data_size = 0;

            request_data = body->request_data;
        }


        auto ret = responder(connection, meth, request_data);

        if(ret.response_code == MHD_HTTP_OK) {

            std::copy(json_response_headers.begin(), json_response_headers.end(), std::back_inserter(ret.headers));

            response << to_string(ret.response);
        }
        return ret;
    }

};

}
#endif //HTTPD_HPP_