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

#include <ext/libcli/libcli.h>
#include <service/cmd/cligen.hpp>
#include <service/cmd/clihelp.hpp>
#include <cfgapi.hpp>

#include <utils/str.hpp>


using namespace libconfig;

CONFIG_MODE_DEF(cli_conf_edit_settings, MODE_EDIT_SETTINGS,"settings")
CONFIG_MODE_DEF(cli_conf_edit_settings_auth, MODE_EDIT_SETTINGS_AUTH,"auth_portal")
CONFIG_MODE_DEF(cli_conf_edit_settings_cli, MODE_EDIT_SETTINGS_CLI,"cli")
CONFIG_MODE_DEF(cli_conf_edit_settings_socks, MODE_EDIT_SETTINGS_SOCKS,"socks")
CONFIG_MODE_DEF(cli_conf_edit_settings_tuning, MODE_EDIT_SETTINGS_TUNING,"tuning")
CONFIG_MODE_DEF(cli_conf_edit_settings_http_api, MODE_EDIT_SETTINGS_HTTP_API,"http_api")

CONFIG_MODE_DEF(cli_conf_edit_debug, MODE_EDIT_DEBUG, "debug")
CONFIG_MODE_DEF(cli_conf_edit_debug_log, MODE_EDIT_DEBUG_LOG, "log")

CONFIG_MODE_DEF(cli_conf_edit_proto_objects, MODE_EDIT_PROTO_OBJECTS, "proto_objects")
CONFIG_MODE_DEF(cli_conf_edit_address_objects, MODE_EDIT_ADDRESS_OBJECTS, "address_objects")
CONFIG_MODE_DEF(cli_conf_edit_port_objects, MODE_EDIT_PORT_OBJECTS, "port_objects")

CONFIG_MODE_DEF(cli_conf_edit_policy, MODE_EDIT_POLICY, "policy")

CONFIG_MODE_DEF(cli_conf_edit_detection_profiles, MODE_EDIT_DETECTION_PROFILES, "detection_profiles")
CONFIG_MODE_DEF(cli_conf_edit_content_profiles, MODE_EDIT_CONTENT_PROFILES, "content_profiles")
CONFIG_MODE_DEF(cli_conf_edit_tls_profiles, MODE_EDIT_TLS_PROFILES, "tls_profiles")
CONFIG_MODE_DEF(cli_conf_edit_alg_dns_profiles, MODE_EDIT_ALG_DNS_PROFILES, "alg_dns_profiles")
CONFIG_MODE_DEF(cli_conf_edit_auth_profiles, MODE_EDIT_AUTH_PROFILES, "auth_profiles")

CONFIG_MODE_DEF(cli_conf_edit_starttls_signatures, MODE_EDIT_STARTTLS_SIGNATURES, "starttls_signatures")
CONFIG_MODE_DEF(cli_conf_edit_detection_signatures, MODE_EDIT_DETECTION_SIGNATURES, "detection_signatures")

CONFIG_MODE_DEF(cli_conf_edit_routing, MODE_EDIT_ROUTING, "routing")

CONFIG_MODE_DEF(cli_conf_edit_captures, MODE_EDIT_CAPTURES, "captures")
CONFIG_MODE_DEF(cli_conf_edit_captures_local, MODE_EDIT_CAPTURES_LOCAL, "local")
CONFIG_MODE_DEF(cli_conf_edit_captures_remote, MODE_EDIT_CAPTURES_REMOTE, "remote")

#ifdef USE_EXPERIMENT
CONFIG_MODE_DEF(cli_conf_edit_experiment, MODE_EDIT_EXPERIMENT, "experiment")
#endif

std::pair<int, std::string> generate_dynamic_groups(struct cli_def *cli, const char *command, char **argv, int argc) {
    auto words = string_split(command, ' ');
    if(words.size() >= 2) {
        int static_mode = cli->mode;
        std::string static_section_path = CliState::get().sections(static_mode);

        if(static_section_path.find(".[x]") != std::string::npos) {
            sx::str::string_replace_all(static_section_path, ".[x]", "");
        }

        // check for existing entry
        _debug(cli, "creating dynamic groups for section %s, mode %d", static_section_path.c_str(), static_mode);

        try {

            [[maybe_unused]]
            auto &parent_settings = CfgFactory::cfg_root().lookup(static_section_path);
            std::string this_setting_path = static_section_path + "." + words[1];

            auto &this_settings = CfgFactory::cfg_root().lookup(this_setting_path);
            int this_index = this_settings.getIndex();
            int new_mode = static_mode + 500 + this_index;

            CliState::get().callbacks(
                    this_setting_path,
                    CliState::callback_entry(new_mode, CliCallbacks(this_setting_path).cmd("set", cli_generic_set_cb)),
                    true); // set mode map, as the map value increases

            cli_generate_set_commands(cli, this_setting_path);

            cli_generate_toggle_commands(cli, this_setting_path);

            return { new_mode, words[1]};

        } catch (ConfigException const& e) {
            cli_print(cli, "error loading %s.%s: %s", static_section_path.c_str(), words[1].c_str(), e.what());
        }
    }

    return { 0, ""};
}


void cfg_generate_cli_hints(Setting& setting, std::vector<std::string>* this_level_names,
                            std::vector<unsigned int>* this_level_indexes,
                            std::vector<std::string>* next_level_names,
                            std::vector<unsigned int>* next_level_indexes) {

    for (unsigned int i = 0; i < (unsigned int) setting.getLength(); i++) {
        Setting &cur_object = setting[(int)i];

        std::string name;
        if(cur_object.getName()) {
            name = cur_object.getName();
        }

        if( cur_object.isScalar() || cur_object.isArray() ) {
            if( ! name.empty() ) {
                if(this_level_names)
                    this_level_names->push_back(name);
            } else {
                if(this_level_indexes)
                    this_level_indexes->push_back(i);
            }
        } else {
            if( ! name.empty() ) {
                if(next_level_names)
                    next_level_names->push_back(name);
            } else {
                if(next_level_indexes)
                    next_level_indexes->push_back(i);
            }
        }
    }
}

void generate_options_combination(cli_def* cli, cli_command* parent, std::vector<std::string> const& options, int mode, CliCallbacks::callback callback, int& max_depth) {

    if(max_depth <= 0) {
        return; // max_depth reached
    }

    for(auto const& opt: options) {

        auto *ret = cli_register_command(cli, parent, opt.c_str(), callback, PRIVILEGE_PRIVILEGED, mode,
                                         " - valid options");

        std::vector<std::string> my_options;
        std::copy_if(options.begin(), options.end(), std::back_inserter(my_options), [&](auto const& elem) { return elem != opt; });

        if(my_options.empty())
            break;

        generate_options_combination(cli, ret, my_options, mode, callback, --max_depth);
    }

}

void cli_generate_set_command_args(struct cli_def *cli, cli_command* parent, std::string const &section, std::string const& varname) {

    auto& cb_entry = CliState::get().callbacks(section);
    auto set_cb = std::get<1>(cb_entry).cmd("set");
    int mode = std::get<0>(cb_entry);

    std::vector<std::string> opts;

    auto cli_e = CliHelp::get().find(section + "." + varname);
    if(not cli_e) {
        std::string masked = sx::str::cli::mask_all(section + "." + varname);
        cli_e = CliHelp::get().find(masked);
    }

    if(cli_e) {
        opts = cli_e->get().suggestion_generate(section, varname);
    }

    auto& this_setting = CfgFactory::cfg_root().lookup((section + "." + varname).c_str());
    auto this_type = this_setting.getType();

    if(this_type != Setting::TypeArray) {
        for(auto const& k: opts) {

            cli_register_command(cli, parent, k.c_str(), set_cb, PRIVILEGE_PRIVILEGED, mode,
                                                    " - valid options");
        }
    } else {
        int max_depth = 10;
        generate_options_combination(cli, parent, opts, mode, set_cb, max_depth);
    }
}


void cli_generate_set_commands (struct cli_def *cli, std::string const &section) {


    auto& this_setting = CfgFactory::cfg_root().lookup(section.c_str());

    std::string this_setting_path = this_setting.getPath();
    _debug(cli, "cli_generate_set_commands: path = %s", this_setting.getPath().c_str());

    auto & cb_entry = CliState::get().callbacks(section);
    auto set_cb = std::get<1>(cb_entry).cmd("set");

    std::string set_help = string_format(" \t - modify variables in %s", section.c_str());
    int mode = std::get<0>(cb_entry);

    std::vector<std::string> attributes, groups;
    std::vector<unsigned int> unnamed_attributes, unnamed_groups;

    _debug(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(this_setting, &attributes, &unnamed_attributes, &groups, &unnamed_groups);

    _debug(cli, "%s hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d", this_setting_path.c_str(),
           (int)attributes.size(), (int)unnamed_attributes.size(),
           (int)groups.size(), (int)unnamed_groups.size());

    if((! unnamed_attributes.empty() ) || (! attributes.empty()) ) {

        std::string name;


        // register anonymous 'set' command bound to CLI 'mode' ID
        auto cli_parent_set = cli_register_command(cli, nullptr, "set", nullptr, PRIVILEGE_PRIVILEGED, mode,
                                                   set_help.c_str());

        for( const auto& here_n: attributes) {

            // create type information, and (possibly) some help text

            std::string help = CliHelp::get().help(CliHelp::help_type_t::HELP_CONTEXT, section, here_n);
            if(help.empty()) {
                help = string_format("modify '%s'", here_n.c_str());
            }

            auto help2 = "\t - " + help;

            auto* ret_single = cli_register_command(cli, cli_parent_set, here_n.c_str(), set_cb, PRIVILEGE_PRIVILEGED, mode,
                                                    help2.c_str() );

            cli_generate_set_command_args(cli, ret_single, section, here_n);

        }
    }
}

void cli_generate_toggle_command_args(struct cli_def *cli, cli_command* parent, std::string const &section, std::string const& varname) {

    auto & cb_entry = CliState::get().callbacks(section);
    auto toggle_cb = std::get<1>(cb_entry).cmd("toggle");
    int mode = std::get<0>(cb_entry);

    std::string masked = sx::str::cli::mask_all(section);
    if(not toggle_cb) {
        // if no specific callback is found, look for masked

        auto& cb_entry_n = CliState::get().callbacks(masked);
        toggle_cb = std::get<1>(cb_entry_n).cmd("toggle");
    }

    std::vector<std::string> opts;
    auto cli_e = CliHelp::get().find(masked + '.' + varname);
    if(cli_e) {
        opts = cli_e->get().suggestion_generate(section, varname);
    }

    for(auto const& o: opts) {
        _debug(cli, "cli_generate_toggle_commands_args:    suggestion = %s", o.c_str());
    }

    auto& this_setting = CfgFactory::cfg_root().lookup((section + "." + varname).c_str());
    auto this_type = this_setting.getType();

    if(this_type == Setting::TypeArray or this_type == Setting::TypeList) {

        _debug(cli, "cli_generate_toggle_commands_args: is list/array");

        std::vector<std::string> cfg_values;


        // add existing values into suggestions (don't forget to dedup it later)

        for(int i = 0; i < this_setting.getLength(); i++) {
            if(not this_setting.isAggregate()) {
                std::string sub = this_setting[i].c_str();
                cfg_values.emplace_back(sub);
            }
        }
        for(auto const& v: cfg_values) {
            opts.emplace_back(v);
            _debug(cli, "cli_generate_toggle_commands_args:    config values = %s", v.c_str());
        }

        opts = CmdCleaner::dedup(opts);
        for(auto const& o: opts) {
            _debug(cli, "cli_generate_toggle_commands_args:    final opts = %s", o.c_str());
        }


//        for(auto const& k: opts) {
//
//            cli_register_command(cli, parent, k.c_str(), toggle_cb, PRIVILEGE_PRIVILEGED, mode,
//                                 " - valid options");
//        }

        if(not opts.empty()) {
            int max_depth = 10;
            generate_options_combination(cli, parent, opts, mode, toggle_cb, max_depth);
        }
    }
}

void cli_generate_toggle_commands (struct cli_def *cli, std::string const &section) {


    auto& this_setting = CfgFactory::cfg_root().lookup(section.c_str());

    std::string this_setting_path = this_setting.getPath();
    _debug(cli, "cli_generate_toggle_commands: path = %s", this_setting.getPath().c_str());

    auto& cb_entry = CliState::get().callbacks(section);
    int mode = std::get<0>(cb_entry);

    auto toggle_cb = std::get<1>(cb_entry).cmd("toggle");
    if(not toggle_cb) {
        auto& cb_entry_n = CliState::get().callbacks(sx::str::cli::mask_all(section));
        toggle_cb = std::get<1>(cb_entry_n).cmd("toggle");
    }

    std::string set_help = string_format(" \t - toggle variables in %s", section.c_str());


    std::vector<std::string> attributes, groups;
    std::vector<unsigned int> unnamed_attributes, unnamed_groups;

    _debug(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(this_setting, &attributes, &unnamed_attributes, &groups, &unnamed_groups);

    _debug(cli, "%s hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d", this_setting_path.c_str(),
           (int)attributes.size(), (int)unnamed_attributes.size(),
           (int)groups.size(), (int)unnamed_groups.size());

    if((! unnamed_attributes.empty() ) || (! attributes.empty()) ) {

        std::string name;


        // register anonymous 'set' command bound to CLI 'mode' ID
        cli_command* cli_parent_toggle = nullptr;

        for( const auto& here_n: attributes) {

            _debug(cli, "cli_generate_toggle_commands:    attribute = %s", here_n.c_str());

            // process only list or array types (avoid 'toggle' command if there are not attributes to toggle)
            if (this_setting.exists(here_n.c_str()) and (
                    this_setting[here_n.c_str()].isList() or this_setting[here_n.c_str()].isArray())) {

                _debug(cli, "cli_generate_toggle_commands:    is list/array");

                if (not cli_parent_toggle) {
                    cli_parent_toggle = cli_register_command(cli, nullptr, "toggle", nullptr, PRIVILEGE_PRIVILEGED, mode,
                                         set_help.c_str());

                    _debug(cli, "cli_generate_toggle_commands:    creating parent command node 0x%p", static_cast<void*>(cli_parent_toggle));
                }

                std::string help = CliHelp::get().help(CliHelp::help_type_t::HELP_CONTEXT, section, here_n);
                if (help.empty()) {
                    help = string_format("toggle '%s'", here_n.c_str());
                }

                auto help2 = "\t - " + help;

                auto *ret_single = cli_register_command(cli, cli_parent_toggle, here_n.c_str(), toggle_cb,
                                                        PRIVILEGE_PRIVILEGED, mode,
                                                        help2.c_str());

                _debug(cli, "cli_generate_toggle_commands:    creating command node 0x%p for '%s', cb = 0x%p",
                       static_cast<void*>(ret_single), here_n.c_str(), reinterpret_cast<void*>(toggle_cb));

                cli_generate_toggle_command_args(cli, ret_single, section, here_n);

            }
        }
    }
}


void cli_generate_move_commands(cli_def* cli, int this_mode, cli_command *move, CliCallbacks::callback callback, int i, int len ) {

    std::string help_move = "move elements in the list";

    auto move_x = cli_register_command(cli, move, string_format("[%d]", i).c_str(),
                                       nullptr, PRIVILEGE_PRIVILEGED, this_mode,
                                       help_move.c_str());

    auto move_x_before = cli_register_command(cli, move_x, "before",
                                              nullptr, PRIVILEGE_PRIVILEGED, this_mode,
                                              help_move.c_str());
    auto move_x_after = cli_register_command(cli, move_x, "after",
                                             nullptr, PRIVILEGE_PRIVILEGED, this_mode,
                                             help_move.c_str());

    if (i > 0) {
        cli_register_command(cli, move_x, "up", callback, PRIVILEGE_PRIVILEGED, this_mode,
                             help_move.c_str());
        cli_register_command(cli, move_x, "top", callback, PRIVILEGE_PRIVILEGED, this_mode,
                             help_move.c_str());
    }
    if (i < len - 1) {
        cli_register_command(cli, move_x, "down", callback, PRIVILEGE_PRIVILEGED, this_mode,
                             help_move.c_str());
        cli_register_command(cli, move_x, "bottom", callback, PRIVILEGE_PRIVILEGED, this_mode,
                             help_move.c_str());
    }


    for (int j = 0; j < len; j++) {
        if (i == j) {
            continue;
        }

        cli_register_command(cli, move_x_before, string_format("[%d]", j).c_str(), callback,
                             PRIVILEGE_PRIVILEGED, this_mode, help_move.c_str());
        cli_register_command(cli, move_x_after, string_format("[%d]", j).c_str(), callback,
                             PRIVILEGE_PRIVILEGED, this_mode, help_move.c_str());
    }

}


void cli_generate_commands (cli_def *cli, std::string const &this_section, cli_command *cli_parent) {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    std::string help_edit = string_format("edit %s sub-items", this_section.c_str());
    std::string help_add = "add elements";
    std::string help_remove = "remove elements";


    auto &cfg_this_section = CfgFactory::cfg_root().lookup(this_section.c_str());
    auto &this_callback_entry = CliState::get().callbacks(this_section);
    int this_mode = std::get<0>(this_callback_entry);

    if(this_mode == 0) {
        cli_print(cli, "%s has no mode setting", this_section.c_str());
        return;
    }

    // common root edit for all editable sub-items
    cli_command* edit = nullptr;
    // common remove for all removable sub-items
    cli_command* remove = nullptr;
    // common remove for all removable sub-items
    cli_command* add = nullptr;
    // common remove for all removable sub-items
    cli_command* cli_move = nullptr;

    for( int i = 0 ; i < cfg_this_section.getLength() ; i++ ) {

        Setting& sub_section = cfg_this_section[i];
        std::string sub_section_name;

        const char* cfg_section_name = sub_section.getName();

        std::stringstream section_ss;
        std::stringstream section_template_ss;

        if(cfg_section_name) {
            sub_section_name = cfg_section_name;

            section_ss << this_section << "." << sub_section_name;
            section_template_ss << this_section << "." << sub_section_name;
        } else {
            sub_section_name = string_format("[%d]", i);
            section_ss << this_section << "." << sub_section_name;
            section_template_ss << this_section << ".[x]";
        }

        std::string section_path = section_ss.str();
        std::string section_template = section_template_ss.str();
        bool templated = false;


        std::string template_key = section_template;
        if(CliState::get().has_callback(template_key)) {
            templated = true;

            // it is possible object is already in callback db (set up by previous cmd generation),
            // but we still need to look for .[x] template!
            _debug(cli, "object %s has callbacks set ", template_key.c_str());
        }
        else if (CliState::get().has_callback(this_section + ".[x]")) {

            _debug(cli, "object %s has no callbacks set, but .[x] found", template_key.c_str());
            template_key = this_section + ".[x]";
            templated = true;
        }
        else {
            _debug(cli, "object %s has callbacks set, no template set", template_key.c_str());
            // otherwise there is no template and template_cb will be the same as section_cb
            template_key = section_path;
        }

        // load template first, section will be created automatically and template selection wouldn't work
        auto& template_cb = CliState::get().callbacks(template_key);




        if(templated and (sub_section.getType() == Setting::TypeGroup or sub_section.getType() == Setting::TypeArray)) {

            // init a new section callback
            if(! CliState::get().has_callback(section_path)) {
                CliState::get().callbacks(section_path) = { this_mode , CliCallbacks(section_path) };
            }
            auto& section_cb = CliState::get().callbacks(section_path);


            // register 'edit' and 'edit <subsection>' in terms of this "mode ID"

            auto edit_enabled  = std::get<1>(template_cb).cap("edit");
            auto remove_enabled = std::get<1>(template_cb).cap("remove");
            auto add_enabled = std::get<1>(template_cb).cap("add");
            auto move_enabled = std::get<1>(template_cb).cap("move");

            _debug(cli, "%s/%s:t=%d: edit: %d, remove: %d, add: %d, move: %d", section_template.c_str(), template_key.c_str(), templated,
                   edit_enabled, remove_enabled, add_enabled, move_enabled);

            if(edit_enabled) {

                auto cb_edit = std::get<1>(template_cb).cmd("edit");

                if(! edit) {
                    // initialize parent "edit command only once"
                    edit = cli_register_command(cli, cli_parent, "edit", nullptr, PRIVILEGE_PRIVILEGED, this_mode,
                                                help_edit.c_str());

                    std::get<1>(template_cb).cli("edit", edit);
                }


                auto edit_sub = cli_register_command(cli, edit, sub_section_name.c_str(),
                                     cb_edit, PRIVILEGE_PRIVILEGED, this_mode,
                                     string_format("edit %s settings", sub_section_name.c_str()).c_str());


                std::get<1>(section_cb).cli("edit", edit_sub);
                std::get<1>(section_cb).cmd("edit", cb_edit);

                if(section_path == template_key) {
                    _debug(cli, "templated, but not dynamic group: %s - generating subcommands", section_path.c_str());
                    cli_generate_commands(cli, section_path, nullptr);
                } else {
                    _debug(cli, "dynamic group: %s - NOT generating subcommands", section_path.c_str());
                }
            }

            if(remove_enabled) {

                auto cb_remove = std::get<1>(template_cb).cmd("remove");

                if(!remove) {
                    remove = cli_register_command(cli, cli_parent, "remove", cb_remove, PRIVILEGE_PRIVILEGED, this_mode, help_remove.c_str());

                    std::get<1>(template_cb).cli("remove", remove);
                }

                auto remove_sub = cli_register_command(cli, remove, sub_section_name.c_str(),
                                     cb_remove, PRIVILEGE_PRIVILEGED, this_mode,
                                     string_format("remove %s element", sub_section_name.c_str()).c_str());

                std::get<1>(section_cb).cli("remove", remove_sub);
                std::get<1>(section_cb).cmd("remove", cb_remove);

            }

            if(add_enabled) {

                if(! add) {
                    auto cb_add = std::get<1>(template_cb).cmd("add");

                    add = cli_register_command(cli, cli_parent, "add",
                                               cb_add, PRIVILEGE_PRIVILEGED, this_mode, help_add.c_str());
                    std::get<1>(template_cb).cli("add", add);
                    std::get<1>(template_cb).cmd("add", cb_add);
                }
            }

            if(move_enabled and not std::get<1>(template_cb).cli("move")) {

                int len = cfg_this_section.getLength();
                std::string help_move = "move elements in the list";

                if(len > 1) {

                    auto cb_move = std::get<1>(template_cb).cmd("move");
                    if(! cli_move) {
                        cli_move = cli_register_command(cli, cli_parent, "move",
                                                        nullptr, PRIVILEGE_PRIVILEGED, this_mode, help_move.c_str());
                        std::get<1>(template_cb).cli("move", cli_move);
                    }

                    for (int i = 0; i < len; i++) {
                        cli_generate_move_commands(cli, this_mode, cli_move, cb_move, i, len);
                    }
                }
            }
        }
    }

    // if previous for loop didn't run, because section is empty
    if(cfg_this_section.getLength() == 0) {

        std::string template_key;

        if (CliState::get().has_callback(this_section + ".[x]")) {

            _debug(cli, "0 elements - new object %s : callback for .[x] found", template_key.c_str());
            template_key = this_section + ".[x]";
        }
        else if(CliState::get().has_callback(this_section)) {
            _debug(cli, "0 elements - new object %s : callback ", template_key.c_str());
            template_key = this_section;
        }

        // template found?
        if(not template_key.empty()) {
            auto& cb = CliState::get().callbacks(template_key);
            auto add_enabled = std::get<1>(cb).cap("add");
            if(add_enabled) {
                if(! add) {
                    auto cb_add = std::get<1>(cb).cmd("add");
                    auto cb_edit = std::get<1>(cb).cmd("edit");
                    auto cb_remove = std::get<1>(cb).cmd("remove");

                    if(cb_add) {
                        add = cli_register_command(cli, cli_parent, "add",
                                                   cb_add, PRIVILEGE_PRIVILEGED, this_mode, help_add.c_str());
                        std::get<1>(cb).cli("add", add);
                        std::get<1>(cb).cmd("add", cb_add);
                    }
                    if(add) {
                        if(cb_edit) {
                            // if added
                            edit = cli_register_command(cli, cli_parent, "edit",
                                                       cb_edit, PRIVILEGE_PRIVILEGED, this_mode, help_add.c_str());
                            std::get<1>(cb).cli("edit", edit);
                            std::get<1>(cb).cmd("edit", cb_edit);
                        }
                        if(cb_remove) {
                            // if added
                            remove = cli_register_command(cli, cli_parent, "remove",
                                                        cb_remove, PRIVILEGE_PRIVILEGED, this_mode, help_add.c_str());
                            std::get<1>(cb).cli("remove", remove);
                            std::get<1>(cb).cmd("remove", cb_remove);
                        }

                    }
                }
            }
        }

    }

    // generate set commands for this section first
    cli_generate_set_commands(cli, this_section);

    cli_generate_toggle_commands(cli, this_section);
}


Setting* cfg_canonize(std::string const& section) {
    auto subparts = string_split(section, '.');
    try {

        Setting* cur = &CfgFactory::cfg_root();

        // divided into sections, potentially with indexes
        for(auto const& subpart: subparts) {

            // split out indexes
            auto sliced = string_split(subpart, '#');

            if(sliced.size() > 1) {
                // we contain # (index(es))
                cur = &cur->lookup(sliced[0]);
                for(unsigned int i = 1; i < sliced.size(); i++) {
                  cur = &cur[std::stoi(sliced[i])];
                }
            }
            else if(! sliced.empty()) {
                // we contain only section name
                cur = &cur->lookup(sliced[0]);
            }
            else {
                // we should not be here (fallback code)
                cur = &cur->lookup(subpart);
            }
        }

        return cur;

    } catch (ConfigException const& e) {
    }

    return nullptr;
}

