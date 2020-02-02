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



std::vector<cli_command*> cfg_generate_cmd_callbacks(std::string& section, struct cli_def* cli, cli_command* cli_parent) {

    if(! cli_parent)
        return {};

    auto& this_setting = CfgFactory::cfg_root().lookup(section.c_str());
    auto const& cb_entry = CliState::get().callback_map[section];
    auto set_cb = std::get<1>(cb_entry).cmd_set();

    int mode = std::get<0>(cb_entry);

    std::vector<std::string> here_name, next_name;
    std::vector<unsigned int> here_index, next_index;

    cli_print(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(this_setting, &here_name, &here_index, &next_name, &next_index);

    cli_print(cli, "hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d",
              (int)here_name.size(), (int)here_index.size(),
              (int)next_name.size(), (int)next_index.size());

    if( (! here_index.empty() ) || (! here_name.empty()) ) {

        std::string name;
        if(this_setting.getName()) {
            //cli_command* cli_here = cli_register_command(cli, cli_parent, this_setting.getName(), set_cb, PRIVILEGE_PRIVILEGED, mode, "modify variables");

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
