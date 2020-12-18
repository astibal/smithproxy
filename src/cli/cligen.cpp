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
#include <cli/cligen.hpp>
#include <cli/clihelp.hpp>
#include <cfgapi.hpp>

CONFIG_MODE_DEF(cli_conf_edit_settings, MODE_EDIT_SETTINGS,"settings");
CONFIG_MODE_DEF(cli_conf_edit_settings_auth, MODE_EDIT_SETTINGS_AUTH,"auth_portal");
CONFIG_MODE_DEF(cli_conf_edit_settings_cli, MODE_EDIT_SETTINGS_CLI,"cli");
CONFIG_MODE_DEF(cli_conf_edit_settings_socks, MODE_EDIT_SETTINGS_SOCKS,"socks");

CONFIG_MODE_DEF(cli_conf_edit_debug, MODE_EDIT_DEBUG, "debug");
CONFIG_MODE_DEF(cli_conf_edit_debug_log, MODE_EDIT_DEBUG_LOG, "log");

CONFIG_MODE_DEF(cli_conf_edit_proto_objects, MODE_EDIT_PROTO_OBJECTS, "proto_objects");
CONFIG_MODE_DEF(cli_conf_edit_address_objects, MODE_EDIT_ADDRESS_OBJECTS, "address_objects");
CONFIG_MODE_DEF(cli_conf_edit_port_objects, MODE_EDIT_PORT_OBJECTS, "port_objects");

CONFIG_MODE_DEF(cli_conf_edit_policy, MODE_EDIT_POLICY, "policy");

CONFIG_MODE_DEF(cli_conf_edit_detection_profiles, MODE_EDIT_DETECTION_PROFILES, "detection_profiles");
CONFIG_MODE_DEF(cli_conf_edit_content_profiles, MODE_EDIT_CONTENT_PROFILES, "content_profiles");
CONFIG_MODE_DEF(cli_conf_edit_tls_profiles, MODE_EDIT_TLS_PROFILES, "tls_profiles");
CONFIG_MODE_DEF(cli_conf_edit_alg_dns_profiles, MODE_EDIT_ALG_DNS_PROFILES, "alg_dns_profiles");
CONFIG_MODE_DEF(cli_conf_edit_auth_profiles, MODE_EDIT_AUTH_PROFILES, "auth_profiles");

CONFIG_MODE_DEF(cli_conf_edit_starttls_signatures, MODE_EDIT_STARTTLS_SIGNATURES, "starttls_signatures");
CONFIG_MODE_DEF(cli_conf_edit_detection_signatures, MODE_EDIT_DETECTION_SIGNATURES, "detection_signatures");


std::pair<int, std::string> generate_dynamic_groups(struct cli_def *cli, const char *command, char **argv, int argc) {
    auto words = string_split(command, ' ');
    if(words.size() >= 2) {
        int static_mode = cli->mode;
        std::string static_section_path = CliState::get().sections(static_mode);

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
                    CliState::callback_entry(new_mode, CliCallbacks().cmd_set(cli_generic_set_cb)));

            cli_generate_set_commands(cli, this_setting_path);

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

std::vector<std::string> load_valid_options(std::string const& section, std::string const& varname) {

    std::vector<std::string> ret;

    auto fill_attributes = [&](std::vector<std::string> keys) {
        for(auto const& k: keys) {
            ret.push_back(k);
        }
    };

    if(section.find("policy.[") == 0) {

        if(varname == "dst" || varname == "src") {
            fill_attributes(CfgFactory::get().keys_of_db_address());
        }
        else if(varname == "proto" ) {
            fill_attributes(CfgFactory::get().keys_of_db_proto());
        }
        else if(varname == "sport" || varname == "dport") {
            fill_attributes(CfgFactory::get().keys_of_db_port());
        }
        else if(varname == "tls_profile") {
            fill_attributes(CfgFactory::get().keys_of_db_prof_tls());
        }
        else if(varname == "detection_profile") {
            fill_attributes(CfgFactory::get().keys_of_db_prof_detection());
        }
        else if(varname == "content_profile") {
            fill_attributes(CfgFactory::get().keys_of_db_prof_content());
        }
        else if(varname == "auth_profile") {
            fill_attributes(CfgFactory::get().keys_of_db_prof_auth());
        }
        else if(varname == "alg_dns_profile") {
            fill_attributes(CfgFactory::get().keys_of_db_prof_alg_dns());
        }
        else if(varname == "nat") {
            fill_attributes( { "none", "auto" } );
        }
        else if(varname == "action") {
            fill_attributes( { "accept", "reject" });
        }
    }

    return ret;
}

std::vector<cli_command*> cli_generate_set_command_args(struct cli_def *cli, cli_command* parent, std::string const &section, std::string const& varname) {

    std::vector<cli_command*> ret;

    auto const& cb_entry = CliState::get().callbacks(section);
    auto set_cb = std::get<1>(cb_entry).cmd_set();
    int mode = std::get<0>(cb_entry);

    auto opts = load_valid_options(section, varname);

    for(auto const& k: opts) {
        auto *ret_single = cli_register_command(cli, parent, k.c_str(), set_cb, PRIVILEGE_PRIVILEGED, mode,
                                                " - valid options");

        ret.push_back(ret_single);
    }

    return ret;

}


std::vector<cli_command *> cli_generate_set_commands (struct cli_def *cli, std::string const &section) {


    auto& this_setting = CfgFactory::cfg_root().lookup(section.c_str());

    std::string this_setting_path = this_setting.getPath();
    _debug(cli, "cli_generate_set_commands: path = %s", this_setting.getPath().c_str());

    auto const& cb_entry = CliState::get().callbacks(section);
    auto set_cb = std::get<1>(cb_entry).cmd_set();

    std::string set_help = string_format(" \t - modify variables in %s", section.c_str());
    int mode = std::get<0>(cb_entry);

    // register anonymous 'set' command bound to CLI 'mode' ID
    auto cli_parent = cli_register_command(cli, nullptr, "set", nullptr, PRIVILEGE_PRIVILEGED, mode,
                                           set_help.c_str());

    std::vector<std::string> attributes, groups;
    std::vector<unsigned int> unnamed_attributes, unnamed_groups;

    _debug(cli, "calling cfg_generate_cli_hints");

    cfg_generate_cli_hints(this_setting, &attributes, &unnamed_attributes, &groups, &unnamed_groups);

    _debug(cli, "%s hint results: named: %d, indexed %d, next-level named: %d, next-level indexed: %d", this_setting_path.c_str(),
           (int)attributes.size(), (int)unnamed_attributes.size(),
           (int)groups.size(), (int)unnamed_groups.size());

    if((! unnamed_attributes.empty() ) || (! attributes.empty()) ) {

        std::string name;


            std::vector<cli_command*> ret;

            for( const auto& here_n: attributes) {

                // create type information, and (possibly) some help text

                std::string help = CliHelp::instance().help(CliHelp::help_type_t::HELP_CONTEXT, section, here_n);
                if(help.empty()) {
                    help = string_format("modify '%s'", here_n.c_str());
                }

                auto help2 = "\t - " + help;

                auto* ret_single = cli_register_command(cli, cli_parent, here_n.c_str(), set_cb, PRIVILEGE_PRIVILEGED, mode,
                                                        help2.c_str() );

                cli_generate_set_command_args(cli, ret_single, section, here_n);

                ret.push_back(ret_single);
            }

            return ret;
    }

    return {};
}


void cli_generate_commands (cli_def *cli, std::string const &section, cli_command *cli_parent) {
    std::scoped_lock<std::recursive_mutex> l_(CfgFactory::lock());

    // generate set commands for this section first
    cli_generate_set_commands(cli, section);

    std::string help_edit = string_format("edit %s sub-items", section.c_str());
    std::string help_add = "add elements";
    std::string help_remove = "remove elements";

    cli_command* edit = nullptr;
    cli_command* add = nullptr;
    cli_command* remove = nullptr;

    auto &this_section = CfgFactory::cfg_root().lookup(section.c_str());
    auto &this_callback_entry = CliState::get().callbacks(section);
    int this_mode = std::get<0>(this_callback_entry);


    for( int i = 0 ; i < this_section.getLength() ; i++ ) {

        Setting& sub_section = this_section[i];

        if(sub_section.getType() == Setting::TypeGroup) {

            std::string sub_section_name;

            const char* cfg_section_name = sub_section.getName();

            std::stringstream section_ss;
            std::stringstream section_template_ss;

            if(cfg_section_name) {
                sub_section_name = cfg_section_name;

                section_ss << section << "." << sub_section_name;
                section_template_ss << section << "." << sub_section_name;
            } else {
                sub_section_name = string_format("[%d]", i);
                section_ss << section << "." << sub_section_name;
                section_template_ss << section << ".[x]";
            }

            std::string section_path = section_ss.str();

            auto& callback_entry = CliState::get().callbacks(section_template_ss.str());
            int mode = std::get<0>(callback_entry);

            // specific treatment of dynamic (unknown groups)
            if( mode == 0 ) {
                // defaulted to parent section callbacks
                callback_entry = CliState::get().callbacks(section);
                mode = static_cast<int> (std::get<0>(callback_entry)) + i;
            }
            auto cb_config = std::get<1>(callback_entry).cmd_config();
            auto cb_remove = std::get<1>(callback_entry).cmd_remove();

            cli_generate_commands(cli, section_path, nullptr);


            // register 'edit' and 'edit <subsection>' in terms of this "mode ID"
            if(! edit) {
                edit = cli_register_command(cli, cli_parent, "edit", nullptr, PRIVILEGE_PRIVILEGED, this_mode, help_edit.c_str());
                std::get<1>(this_callback_entry).cli_edit(edit);

            }

            if(! remove) {
                remove = cli_register_command(cli, cli_parent, "remove", cb_remove, PRIVILEGE_PRIVILEGED, this_mode, help_remove.c_str());
                std::get<1>(this_callback_entry).cli_remove(remove);
            }

            cli_register_command(cli, edit, sub_section_name.c_str(),
                                 cb_config, PRIVILEGE_PRIVILEGED, this_mode,
                                 string_format("edit %s settings", sub_section_name.c_str()).c_str());

            cli_register_command(cli, remove, sub_section_name.c_str(),
                                 cb_remove, PRIVILEGE_PRIVILEGED, this_mode,
                                 string_format("remove %s element", sub_section_name.c_str()).c_str());

        }
    }

    auto cb_add = std::get<1>(this_callback_entry).cmd_add();

    add = cli_register_command(cli, cli_parent, "add", cb_add, PRIVILEGE_PRIVILEGED, this_mode, help_add.c_str());
    std::get<1>(this_callback_entry).cli_add(add);
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

void string_replace_all(std::string& target, std::string const& what, std::string const& replacement) {

    auto pos = target.find(what);

    while( pos != std::string::npos ) {

        // Replace this occurrence of Sub String
        target.replace(pos, what.size(), replacement);
        // Get the next occurrence from the current position
        pos = target.find(what,pos + replacement.size());
    }
}
