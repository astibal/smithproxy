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


#include <cli/cligen.hpp>
#include <cli/clihelp.hpp>
#include <cfgapi.hpp>

CONFIG_MODE_DEF(cli_conf_edit_settings, MODE_EDIT_SETTINGS,"settings");
CONFIG_MODE_DEF(cli_conf_edit_settings_auth, MODE_EDIT_SETTINGS_AUTH,"auth_portal");
CONFIG_MODE_DEF(cli_conf_edit_settings_cli, MODE_EDIT_SETTINGS_CLI,"cli");
CONFIG_MODE_DEF(cli_conf_edit_settings_socks, MODE_EDIT_SETTINGS_SOCKS,"socks");

CONFIG_MODE_DEF(cli_conf_edit_debug, MODE_EDIT_DEBUG, "debug");

CONFIG_MODE_DEF(cli_conf_edit_proto_objects, MODE_EDIT_PROTO_OBJECTS, "proto_objects");

CONFIG_MODE_DEF(cli_conf_edit_port_objects, MODE_EDIT_PORT_OBJECTS, "port_objects");


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



std::vector<cli_command *> cli_generate_set_commands (struct cli_def *cli, std::string const &section) {


    auto& this_setting = CfgFactory::cfg_root().lookup(section.c_str());
    auto const& cb_entry = CliState::get().callback_map[section];
    auto set_cb = std::get<1>(cb_entry).cmd_set();

    std::string set_help = string_format(" \t - modify variables in %s", section.c_str());
    int mode = std::get<0>(cb_entry);

    // register anonymous 'set' command bound to CLI 'mode' ID
    auto cli_parent = cli_register_command(cli, nullptr, "set", nullptr, PRIVILEGE_PRIVILEGED, mode,
                                           set_help.c_str());

    std::vector<std::string> here_name, next_name;
    std::vector<unsigned int> here_index, next_index;

    _debug(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(this_setting, &here_name, &here_index, &next_name, &next_index);

    _debug(cli, "hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d",
              (int)here_name.size(), (int)here_index.size(),
              (int)next_name.size(), (int)next_index.size());

    if( (! here_index.empty() ) || (! here_name.empty()) ) {

        std::string name;
        if(this_setting.getName()) {

            std::vector<cli_command*> ret;

            for( const auto& here_n: here_name) {

                // create type information, and (possibly) some help text

                std::string help = CliHelp::instance().help(CliHelp::help_type_t::HELP_CONTEXT, section, here_n);
                if(help.empty()) {
                    help = string_format("modify '%s'", here_n.c_str());
                }

                auto help2 = "\t - " + help;

                auto* ret_single = cli_register_command(cli, cli_parent, here_n.c_str(), set_cb, PRIVILEGE_PRIVILEGED, mode,
                                                        help2.c_str() );
                ret.push_back(ret_single);
            }

            return ret;
        }
    }

    return {};
}


void cli_generate_commands (cli_def *cli, std::string const &section, cli_command *cli_parent) {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());


    // generate set commands for this section first
    cli_generate_set_commands(cli, section);

    std::string help = string_format("edit %s sub-items", section.c_str());

    cli_command* edit = nullptr;

    auto &this_section = CfgFactory::cfg_root().lookup(section.c_str());
    auto this_callback_entry = CliState::get().callback_map[section];
    int this_mode = std::get<0>(this_callback_entry);


    for( int i = 0 ; i < this_section.getLength() ; i++ ) {

        Setting& sub_section = this_section[i];
        std::string sub_section_name = sub_section.getName();

        if(sub_section.getType() == Setting::TypeGroup) {

            std::string section_path = section;
            section_path += "." + sub_section_name;

            auto& callback_entry = CliState::get().callback_map[section_path];
            int mode = std::get<0>(callback_entry);

            // specific treatment of dynamic (unknown groups)
            if( mode == 0 ) {
                // defaulted to parent section callbacks
                callback_entry = CliState::get().callback_map[section];
                mode = static_cast<int> (std::get<0>(callback_entry)) + i;
            }
            auto cb_config = std::get<1>(callback_entry).cmd_config();

//            auto set_cmd = cli_register_command(cli, nullptr, "set", nullptr, PRIVILEGE_PRIVILEGED,
//                                                mode, std::string("set section " + sub_section_name + "variables").c_str());

            cli_generate_commands(cli, section_path, nullptr);


            // register 'edit' and 'edit <subsection>' in terms of this "mode ID"
            if(! edit) {
                edit = cli_register_command(cli, cli_parent, "edit", nullptr, PRIVILEGE_PRIVILEGED, this_mode, help.c_str());
            }
            cli_register_command(cli, edit, sub_section_name.c_str(),
                                 cb_config, PRIVILEGE_PRIVILEGED, this_mode,
                                 string_format("edit %s settings", sub_section_name.c_str()).c_str());
        }
    }
}
