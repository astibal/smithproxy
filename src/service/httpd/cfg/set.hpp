#ifndef HTTPD_SET_HPP_
#define HTTPD_SET_HPP_

#include <ext/json/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/httpd.hpp>
#include <service/httpd/jsonize.hpp>

#include <main.hpp>
#include <service/cfgapi/cfgapi.hpp>

namespace sx::webserver {

    using nlohmann::json;
    using namespace libconfig;

    nlohmann::json json_set_section_entry(struct MHD_Connection * connection, std::string const& meth, std::string const& req) {


        /*      request example (auth token is processed earlier)
         *      {
         *          "token": "<>",
         *          "params" : {
         *              "section": "port_objects",
         *              "name": "to_change",
         *              changeset: {
         *                  "start": "123",
         *                  "comment": "just changed"
         *              }
         *          }
         *      }
         * */

        if(req.empty()) return { "error", "request empty" };

        auto section_name = jsonize::load_json_params<std::string>(req, "section").value_or("");
        auto cfg_name = jsonize::load_json_params<std::string>(req, "name").value_or("");

        auto lc_ = std::scoped_lock(CfgFactory::lock());


        if(section_name.empty() or cfg_name.empty()) {
            return { { "error", "parameters needed: 'section', 'name'" } };
        }
        else {
            unsigned cur_write_status {0};
            std::stringstream cur_write_msg;

            try {
                std::string fullpath = section_name + "." + cfg_name;

                auto& conf = CfgFactory::cfg_obj().lookup(fullpath.c_str());
                auto changeset =  jsonize::load_json_params<json>(req, "changeset").value_or("{}");

                for(auto const& [key, val]: changeset.items()) {

                    // add values depending on
                    std::string varname = key;
                    std::vector<std::string> values;
                    if(val.is_array()) {
                        for(auto arr_e: val.items()) {
                            values.emplace_back(arr_e.value().get<std::string>());
                        }
                    } else {
                        values.emplace_back(val.get<std::string>());
                    }
                    auto [ write_status, write_msg ] = CfgFactory::get()->cfg_write_value(conf, false, varname, values);
                    if(write_status) {
                        ++cur_write_status;
                        cur_write_msg << "OK(" << write_msg << ");";
                    }
                    else {
                        cur_write_msg << "ER(" << write_msg << ");";
                    }
                }

            } catch(libconfig::ConfigException const& e) {
                cur_write_msg <<  string_format("EX(%s);", e.what());
            } catch(json::exception const& e) {
                cur_write_msg <<  string_format("EX(%s);", e.what());
            }

            if(cur_write_status > 0) {
                CfgFactory::get()->board()->upgrade("API");
                if (not CfgFactory::get()->apply_config_change(section_name)) {
                    cur_write_msg << "ER(config not applied);";
                }

                return { { "success", cur_write_msg.str() } };
            }
            else {
                return { { "error", cur_write_msg.str() } };
            }
        }
    }
}

#endif