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

#ifndef HTTPD_ADD_HPP_
#define HTTPD_ADD_HPP_

#include <ext/json/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/jsonize.hpp>

#include <main.hpp>
#include <service/cfgapi/cfgapi.hpp>

namespace sx::webserver {

    using nlohmann::json;

    nlohmann::json json_add_section_entry(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {

        /*      request example (auth token is processed earlier)
         *      {
         *          "token": "<>",
         *          "params" : {
         *              "section": "port_objects",
         *              "name": "to_change",
         *          }
         *      }
         * */

        if(req.empty()) return { "error", "request empty" };

        auto section_name = jsonize::load_json_params<std::string>(req, "section").value_or("");
        auto varname = jsonize::load_json_params<std::string>(req, "name").value_or("");

        if(not section_name.empty() and not varname.empty()) {
            json ret;

            std::vector<std::string> args;
            args.emplace_back(varname);

            auto [ prep_status, prep_msg ] = CfgFactory::cfg_add_prepare_params(section_name, args);
            if(not prep_status) {
                return { {"error", prep_msg } };
            }
            else {
                // parameters satisfy requirements
                auto lc_ = std::scoped_lock(CfgFactory::lock());
                auto add_status = CfgFactory::get()->cfg_add_entry(section_name, args[0]);
                if(add_status.first) {
                    CfgFactory::board()->upgrade("API");
                }
                return jsonize::cfg_status_response(add_status);
            }

        } else {
            return { { "error", "parameters needed: 'section', 'name'" } };
        }
    }
}

#endif