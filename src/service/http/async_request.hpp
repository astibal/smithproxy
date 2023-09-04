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

#ifndef SX_HTTP_ASYNCREQUEST
#define SX_HTTP_ASYNCREQUEST

#include <iostream>
#include <string>
#include <optional>

#include <service/tpool.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/request.hpp>
#include <log/logger.hpp>

namespace sx::http {

    class AsyncRequestException : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    class AsyncRequest {
        static inline std::once_flag once_flag;
        static inline std::unique_ptr<AsyncRequest> asr;

    public:

        struct config {
            static inline long timeout = 5;
        };

        static AsyncRequest& get() {
            std::call_once(once_flag, []() {
                asr = std::make_unique<AsyncRequest>();
            });

            if(not asr) {
                throw AsyncRequestException("async request was not initialized");
            }

            return *asr;
        }


        using expected_reply = std::optional<std::pair<long,std::string>>;
        using reply_hook = std::function<void(expected_reply const&)>;

        static bool emit(std::string const& url, std::string const& pay, reply_hook const& hook) {
            auto &pool = ThreadPool::instance::get();
            auto ret = pool.enqueue([url, pay, &hook]([[maybe_unused]] std::atomic_bool const &stop_flag) {

                std::string zip;
                {
                    auto lc_ = std::scoped_lock(CfgFactory::lock());
                    auto const &nms = CfgFactory::get()->db_nameservers;

                    std::ostringstream oss;
                    for (size_t i = 0; i < nms.size(); ++i) {
                        oss << nms[i].str_host;     // loaded from config, string should always be there
                        if (i < nms.size() - 1) {
                            oss << ",";
                        }
                    }
                    zip = oss.str();
                }

                Request r(Request::DEFAULT, zip);
                r.set_timeout(config::timeout);
                auto reply = r.emit(url, pay);

                if(not reply or reply.value().first >= 300) {
                    long code = reply.has_value() ? reply->first : -1;
                    std::string msg = reply.has_value() ? reply->second : "request failed";

                    Log::get()->events().insert(ERR, "error in request '%s': %d:%s", url.c_str(), code, msg.c_str());
                }

                hook(reply);
            });

            return (ret > 0);
        };
    };
}

#endif