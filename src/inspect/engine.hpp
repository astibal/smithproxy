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

#ifndef ENGINE_HPP
#define ENGINE_HPP


#include <any>

#include <sobject.hpp>
#include <inspect/sxsignature.hpp>

class MitmHostCX;

namespace sx::engine {

    struct ApplicationData: public socle::sobject {
        ~ApplicationData() override = default;
        bool is_ssl = false;
        std::unordered_map<std::string,std::string> properties;

        virtual std::string original_request() { return request(); }; // parent request
        virtual std::string request() { return std::string(""); };
        virtual std::string protocol() const = 0;

        bool ask_destroy() override { return false; };

        std::string properties_str() const {
            std::stringstream ss;

            if (is_ssl) ss << "[ssl=true]";
            if (not properties.empty()) {
                ss << "+";
                for (auto const &[k, v]: properties) {
                    ss << "[" << k << "=" << v << "]";
                }
            }
            return ss.str();
        }

        std::string to_string(int verbosity) const override {

            if(verbosity >= iDEB) {
                return properties_str();
            }

            return {};
        };

        TYPENAME_OVERRIDE("ApplicationData")

    private:
        logan_lite log {"com.app"};
    };

    // Free-form application data

    struct CustomApplicationData : public ApplicationData {
        explicit CustomApplicationData(std::string_view n): proto_name(n) {};
        CustomApplicationData(std::string_view  n, std::string_view  r): proto_name(n), request(r) {};

        std::string protocol() const override { return proto_name; };

        std::string to_string(int ver) const override {
            std::stringstream r;
            r << proto_name;
            if(not request.empty()) r << ":" << request;

            if(not properties.empty()) {
                r << ":" << properties_str();
            }

            return r.str();
        }

        std::string proto_name;
        std::string request;
    };

    struct EngineCtx {
        MitmHostCX* origin = nullptr;
        std::shared_ptr<duplexFlowMatch> signature;
        std::size_t flow_pos = 0;
        std::shared_ptr<ApplicationData> application_data;

        // state data to be placed here
        std::any state_info;  // general positional information, etc
        std::any state_data;  // more application specific data


        // status
        enum class status_t { START, MAGIC, OK, ERROR };
        status_t status {status_t::START};
    };

}

#endif