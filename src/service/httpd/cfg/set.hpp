#ifndef HTTPD_SET_HPP_
#define HTTPD_SET_HPP_

#include <nlohmann/json.hpp>

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <service/httpd/httpd.hpp>
#include <service/http/jsonize.hpp>

#include <main.hpp>
#include <service/cfgapi/cfgapi.hpp>

namespace sx::webserver {

    using nlohmann::json;
    using namespace libconfig;

    class ConfigGroupRollback {
    public:
        explicit ConfigGroupRollback(Setting& target): target_(target) {
            saved_ = &backup_.getRoot().add("saved", Setting::TypeGroup);
            CfgFactory::cfg_clone_setting(*saved_, target_);
        }

        ~ConfigGroupRollback() { restore(); }

        void commit() noexcept { active_ = false; }

        void restore() noexcept {
            if(not active_) return;
            try {
                for(int i = target_.getLength() - 1; i >= 0; --i) target_.remove(i);
                CfgFactory::cfg_clone_setting(target_, *saved_);
            }
            catch(...) {
                // Best effort during exception unwinding; never mask the
                // original configuration error.
            }
            active_ = false;
        }

    private:
        Setting& target_;
        Config backup_;
        Setting* saved_ = nullptr;
        bool active_ = true;
    };

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
        auto changeset = jsonize::load_json_params<json>(req, "changeset");

        auto lc_ = std::scoped_lock(CfgFactory::lock());


        if(section_name.empty() or cfg_name.empty() or not changeset.has_value()) {
            return { { "error", "parameters needed: 'section', 'name', 'changeset'" } };
        }
        else if(not changeset->is_object() or changeset->empty()) {
            return { { "error", "'changeset' must be a non-empty object" } };
        }
        else {
            std::stringstream cur_write_msg;

            try {
                std::string fullpath = section_name + "." + cfg_name;

                auto& conf = CfgFactory::cfg_obj().lookup(fullpath.c_str());
                if(conf.getType() != Setting::TypeGroup) {
                    return { { "error", "configuration target must be a group" } };
                }

                ConfigGroupRollback rollback(conf);

                bool write_failed = false;

                for(auto const& [key, val]: changeset->items()) {

                    std::string varname = key;
                    std::vector<std::string> values;
                    if(val.is_array()) {
                        for(auto const& arr_e: val) {
                            if(not arr_e.is_string()) {
                                cur_write_msg << "ER(values must be strings);";
                                write_failed = true;
                                break;
                            }
                            values.emplace_back(arr_e.get<std::string>());
                        }
                    } else if(val.is_string()) {
                        values.emplace_back(val.get<std::string>());
                    } else {
                        cur_write_msg << "ER(values must be strings);";
                        write_failed = true;
                    }

                    if(write_failed) break;

                    auto [ write_status, write_msg ] = CfgFactory::get()->cfg_write_value(conf, false, varname, values);
                    if(write_status) {
                        cur_write_msg << "OK(" << write_msg << ");";
                    }
                    else {
                        cur_write_msg << "ER(" << write_msg << ");";
                        write_failed = true;
                        break;
                    }
                }

                if(write_failed) {
                    rollback.restore();
                    return { { "error", cur_write_msg.str() } };
                }

                rollback.commit();
                CfgFactory::get()->board()->upgrade("API");
                if (not CfgFactory::get()->apply_config_change(section_name)) {
                    cur_write_msg << "ER(config not applied);";
                }

                return { { "success", cur_write_msg.str() } };

            } catch(libconfig::ConfigException const& e) {
                cur_write_msg <<  string_format("EX(%s);", e.what());
            } catch(json::exception const& e) {
                cur_write_msg <<  string_format("EX(%s);", e.what());
            }
            return { { "error", cur_write_msg.str() } };
        }
    }
}

#endif
