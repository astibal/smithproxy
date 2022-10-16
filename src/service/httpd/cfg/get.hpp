#ifndef HTTPD_GET_HPP_
#define HTTPD_GET_HPP_

#include <ext/json/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/jsonize.hpp>

#include <main.hpp>
#include <service/cfgapi/cfgapi.hpp>

namespace sx::webserver {

    using nlohmann::json;
    using namespace libconfig;

    nlohmann::json json_get_section_entry(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {


        /*      request example (auth token is processed earlier)
         *      {
         *          "token": "<>",
         *          "params" : {
         *              "section": "port_objects",
         *              "name": "exiting",
         *          }
         *      }
         * */

        if(req.empty()) return { "error", "request empty" };

        auto section_name = jsonize::load_json_params<std::string>(req, "section").value_or("");
        auto cfg_name = jsonize::load_json_params<std::string>(req, "name").value_or("");

        auto lc_ = std::scoped_lock(CfgFactory::lock());


        if(section_name.empty()) {
            return { { "error", "parameters needed: 'section', 'name'" } };
        }
        else {
            bool retrieved_status = false;
            std::string ret_status;
            json ret_value;

            std::string fullpath = cfg_name.empty() ? section_name : section_name + "." + cfg_name;
            try {

                auto& conf = CfgFactory::cfg_obj().lookup(fullpath.c_str());

                ret_value = jsonize::from(conf);
                retrieved_status = true;

            } catch(libconfig::ConfigException const& e) {
                ret_status = string_format("EX(%s);", e.what());
            } catch(json::exception const& e) {
                ret_status = string_format("EX(%s);", e.what());
            }

            if(retrieved_status) {
                json rj;
                rj[fullpath] = ret_value;

                return { { "success" , rj } };
            }
            else {
                return { {"error", ret_status } };
            }
        }
    }
}

#endif