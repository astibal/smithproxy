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
#ifndef SMITHPROXY_CLIGEN_HPP
#define SMITHPROXY_CLIGEN_HPP

#include <cfgapi.hpp>
#include <libcli.h>

#include <vector>
#include <string>

#include <cli/cmdserver.hpp>

void cfg_generate_cli_hints(Setting& setting, std::vector<std::string>* this_level_names,
                            std::vector<unsigned int>* this_level_indexes,
                            std::vector<std::string>* next_level_names,
                            std::vector<unsigned int>* next_level_indexes);



std::vector<cli_command*> cfg_generate_cmd_callbacks(std::string& section, struct cli_def* cli, cli_command* cli_parent);



#define CONFIG_MODE_DEC(fn) \
                            \
int fn(struct cli_def *cli, const char *command, char *argv[], int argc); \


#define CONFIG_MODE_DEF(fn, mode, name) \
                                        \
int fn(struct cli_def *cli, const char *command, char *argv[], int argc) { \
    _debug(cli, "entering " name ", mode %d", mode);                       \
                                                                           \
    cli_set_configmode(cli, mode, name );                        \
                                                                 \
    return CLI_OK;                                               \
}    \

#define _debug   if(CliState::get().cli_debug_flag) cli_print



//
//  Functions to execute when issuing 'edit <something>' in config term mode
//
//      - change to conf-term-something
//


enum edit_settings { MODE_EDIT_SETTINGS=40000, MODE_EDIT_SETTINGS_AUTH, MODE_EDIT_SETTINGS_CLI, MODE_EDIT_SETTINGS_SOCKS };

CONFIG_MODE_DEC(cli_conf_edit_settings);
CONFIG_MODE_DEC(cli_conf_edit_settings_auth);
CONFIG_MODE_DEC(cli_conf_edit_settings_cli);
CONFIG_MODE_DEC(cli_conf_edit_settings_socks);


#endif //SMITHPROXY_CLIGEN_HPP
