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
#include <ext/libcli/libcli.h>

#include <vector>
#include <string>

#include <cmd/cmdserver.hpp>
#include <cmd/clistate.hpp>

#define _debug   if(CliState::get().cli_debug_flag) cli_print

void cfg_generate_cli_hints(Setting& setting, std::vector<std::string>* this_level_names,
                            std::vector<unsigned int>* this_level_indexes,
                            std::vector<std::string>* next_level_names,
                            std::vector<unsigned int>* next_level_indexes);



void cli_generate_set_commands (struct cli_def *cli, std::string const& section);
void cli_generate_toggle_commands (struct cli_def *cli, std::string const& section);

void cli_generate_move_commands(cli_def* cli, int this_mode, cli_command *move, CliCallbacks::callback callback, int i, int len);
void cli_generate_commands (cli_def *cli, std::string const &this_section, cli_command *cli_parent);


#define CONFIG_MODE_DEC(fn) \
                            \
int fn(struct cli_def *cli, const char *command, char *argv[], int argc); \


std::pair<int, std::string> generate_dynamic_groups(struct cli_def *cli, const char *command, char **argv, int argc);

#define CONFIG_MODE_DEF(fn, mode, name) \
                                        \
int fn(struct cli_def *cli, const char *command, char *argv[], int argc) { \
    _debug(cli, "entering " name ", mode = %d", mode);                     \
    debug_cli_params(cli, command, argv, argc);                            \
                                                                           \
    int oldmode = cli_set_configmode(cli, mode, name );                    \
    _debug(cli, "   oldmode = %d", oldmode);                               \
                                                                           \
    if(mode == oldmode) {                                                  \
         auto dynres =                                                     \
                        generate_dynamic_groups(cli, command, argv, argc); \
          if (dynres.first > 0) cli_set_configmode(cli, dynres.first, dynres.second.c_str()); \
    }                                                                      \
    return CLI_OK;                                                         \
}    \


//
//  Functions to execute when issuing 'edit <something>' in config term mode
//
//      - change to conf-term-something
//


Setting* cfg_canonize(std::string const& section);

enum edit_settings { MODE_EDIT_SETTINGS=0x10000000, MODE_EDIT_SETTINGS_AUTH=0x10001000, MODE_EDIT_SETTINGS_CLI=0x10002000, MODE_EDIT_SETTINGS_SOCKS=0x10003000 };

CONFIG_MODE_DEC(cli_conf_edit_settings);
CONFIG_MODE_DEC(cli_conf_edit_settings_auth);
CONFIG_MODE_DEC(cli_conf_edit_settings_cli);
CONFIG_MODE_DEC(cli_conf_edit_settings_socks);


enum edit_debug { MODE_EDIT_DEBUG=0x11000000, MODE_EDIT_DEBUG_LOG };
CONFIG_MODE_DEC(cli_conf_edit_debug);
CONFIG_MODE_DEC(cli_conf_edit_debug_log);

enum edit_proto_objects { MODE_EDIT_PROTO_OBJECTS=0x12000000, };
CONFIG_MODE_DEC(cli_conf_edit_proto_objects);


enum edit_address_objects { MODE_EDIT_ADDRESS_OBJECTS=0x13000000, };
CONFIG_MODE_DEC(cli_conf_edit_address_objects);


enum edit_port_objects { MODE_EDIT_PORT_OBJECTS=0x14000000, };
CONFIG_MODE_DEC(cli_conf_edit_port_objects);

enum edit_policy { MODE_EDIT_POLICY=0x15000000, };
CONFIG_MODE_DEC(cli_conf_edit_policy);

enum edit_detection_profile { MODE_EDIT_DETECTION_PROFILES=0x16000000, };
CONFIG_MODE_DEC(cli_conf_edit_detection_profiles);

enum edit_content_profile { MODE_EDIT_CONTENT_PROFILES=0x17000000, };
CONFIG_MODE_DEC(cli_conf_edit_content_profiles);

enum edit_tls_profile { MODE_EDIT_TLS_PROFILES=0x18000000, };
CONFIG_MODE_DEC(cli_conf_edit_tls_profiles);

enum edit_alg_dns_profile { MODE_EDIT_ALG_DNS_PROFILES=0x19000000, };
CONFIG_MODE_DEC(cli_conf_edit_alg_dns_profiles);

enum edit_auth_profile { MODE_EDIT_AUTH_PROFILES=0x1a000000, };
CONFIG_MODE_DEC(cli_conf_edit_auth_profiles);

enum edit_starttls_signatures { MODE_EDIT_STARTTLS_SIGNATURES=0x26000000, };
CONFIG_MODE_DEC(cli_conf_edit_starttls_signatures);


enum edit_detection_signatures { MODE_EDIT_DETECTION_SIGNATURES=0x27000000, };
CONFIG_MODE_DEC(cli_conf_edit_detection_signatures);


#endif //SMITHPROXY_CLIGEN_HPP
