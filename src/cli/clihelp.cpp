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
#include <algorithm>

#include <ext/libcli/libcli.h>

#include <cli/clihelp.hpp>
#include <cli/cligen.hpp>
#include <common/log/logan.hpp>
#include <cfgapi.hpp>

void CliHelp::init() {
    add("default", "")
    .help_quick("enter <value>");

    add("settings.accept_tproxy", "whether to accept incoming connections via TPROXY")
            .help_quick("<bool>: set to 'true' to disable tproxy acceptor (default: false)");

    add("settings.accept_redirect", "whether to accept incoming connections via REDIRECT")
            .help_quick("<bool>: set to 'true' to disable redirect acceptor (default: false)");

    add("settings.accept_socks", "whether to accept incoming connections via SOCKS")
            .help_quick("<bool>: set to 'true' to disable socks acceptor (default: false)");

    add("settings.certs_path", "directory for TLS-resigning CA certificate and key")
            .help_quick("<string>: (default: /etc/smithproxy/certs/default)")
            .may_be_empty(false)
            .value_filter(CliElement::VALUE_DIR);

    add("settings.certs_ctlog", "file containing certificate transparency log list")
            .help_quick("<string>: file with certificate transparency keys (default: ct_log_list.cnf)")
            .value_filter(CliElement::VALUE_FILE);

    add("settings.certs_ca_key_password", "TLS-resigning CA private key protection password")
            .help_quick("<string>: enter string value");

    add("settings.ca_bundle_path", "trusted CA store path (to verify server-side connections)")
            .help_quick("<string>: enter valid path")
            .may_be_empty(false)
            .value_filter(CliElement::VALUE_DIR);



    auto port_check = [](std::string const& v) -> CliElement::value_filter_retval {

        auto [ may_val, descr ] = CliElement::VALUE_UINT_NZ(v);
        auto err = "port value must be a number in range <1024,65535>";

        if(may_val.has_value()) {
            int port_value = std::any_cast<int>(may_val);

            if(port_value < 1024 or port_value > 65535)
                return std::make_pair(std::any(), err);
            else
                return { may_val, "" };
        }

        return { may_val, err };
    };
    add("settings.plaintext_port", "base divert port for non-SSL TCP traffic")
            .help_quick("<string>: string value of port number")
            .may_be_empty(false)
            .value_filter(port_check);

    add("settings.plaintext_workers", "non-SSL TCP traffic worker thread count");
    add("settings.ssl_port", "base divert port for SSL TCP traffic");
    add("settings.ssl_workers", "SSL TCP traffic worker thread count");
    add("settings.ssl_autodetect", "Detect TLS ClientHello on unusual ports");
    add("settings.ssl_autodetect_harder", "Detect TSL ClientHello - wait a bit longer");
    add("settings.ssl_ocsp_status_ttl", "hardcoded TTL for OCSP response validity");
    add("settings.ssl_crl_status_ttl", "hardcoded TTL for downloaded CRL files");

    add("settings.udp_port", "base divert port for non-DTLS UDP traffic");
    add("settings.udp_workers", "non-DTLS traffic worker thread count");

    add("settings.dtls_port", "base divert port for DTLS UDP traffic");
    add("settings.dtls_workers", "DTLS traffic worker thread count");

    add("settings.socks_port", "base SOCKS proxy listening port");
    add("settings.socks_workers", "SOCKS proxy traffic thread count");

    add("settings.log_level", "file logging verbosity level");
    add("settings.log_file", "log file");
    add("settings.log_console", "toggle logging to standard output");
    add("settings.syslog_server", "IP address of syslog server");
    add("settings.syslog_port", "syslog server port");
    add("settings.syslog_facility", "syslog facility");
    add("settings.syslog_level", "syslog logging verbosity level");
    add("settings.syslog_family", "IPv4 or IPv6?");
    add("settings.sslkeylog_file", "where to dump TLS keying material");
    add("settings.messages_dir", "replacement text directory");
    add("settings.write_payload_dir", "root directory for packet dumps");
    add("settings.write_payload_file_prefix", "packet dumps file prefix");
    add("settings.write_payload_file_suffix", "packet dumps file suffix");

    add("settings.auth_portal", "** configure authentication portal settings");
    add("settings.cli", "** configure CLI specific settings");
    add("settings.socks", "** configure SOCKS specific settings");







    help_quick("settings.plaintext_workers", "tproxy non-tls acceptor subordinate threads count");
    help_quick("settings.ssl_port", "tproxy tls acceptor port number");
    help_quick("settings.ssl_workers", "tproxy acceptor subordinate threads count");
    help_quick("settings.ssl_autodetect", "try to detect tls in non-tls connection (tiny delay)");
    help_quick("settings.ssl_autodetect_harder", "try to detect tls in non-tls connection harder");
    help_quick("settings.ssl_ocsp_status_ttl", "obsoleted");
    help_quick("settings.ssl_crl_status_ttl", "obsoleted");
    help_quick("settings.udp_port", "tproxy udp acceptor port number");
    help_quick("settings.udp_workers", "tproxy udp acceptor subordinate threads count");
    help_quick("settings.dtls_port", "nyi - tproxy dtls acceptor port number");
    help_quick("settings.dtls_workers", "nyi - tproxy dtls acceptor subordinate threads count");
    help_quick("settings.socks_port", "socks acceptor port number");
    help_quick("settings.socks_workers", "socks acceptor subordinate threads count");
    help_quick("settings.log_level", "obsoleted");
    help_quick("settings.log_file", "logfile path, must contain %%s for tenant name expansion");
    help_quick("settings.log_console", "obsoleted");
    help_quick("settings.syslog_server", "syslog server IP");
    help_quick("settings.syslog_port", "syslog server port");
    help_quick("settings.syslog_facility", "syslog facility (default 23 = local7)");
    help_quick("settings.syslog_level", "syslog level (default 6 = informational)");
    help_quick("settings.syslog_family", "set to 4 or 6 for ip version");
    help_quick("settings.sslkeylog_file", "file path where to dump tls keys (if set)");
    help_quick("settings.messages_dir", "directory path to message files");
    help_quick("settings.write_payload_dir", "directory path for payload dump files");
    help_quick("settings.write_payload_file_prefix", "dump filename prefix");
    help_quick("settings.write_payload_file_suffix", "dump filename suffix");
    help_quick("settings.auth_portal", "");
    help_quick("settings.cli", "");
    help_quick("settings.socks", "");

    add("debug.log_data_crc", "calculate received CRC data (helps to identify proxy bugs)");

    add("proto_objects", "IP protocols");
    add("proto_objects.[x].id", "IP protocol number (tcp=6, udp=17)");

    add("port_objects", "TCP/UDP ports");
    add("port_objects[x].start", "port range start");
    add("port_objects[x].end", "port range end");

    add("policy.[x].proto", "protocol to match (see proto_objects)")
        .may_be_empty(false);

}


bool CliHelp::value_check(std::string const& varname, int v, cli_def* cli) {
    return true;
}

bool CliHelp::value_check(std::string const& varname, long long int v, cli_def* cli) {
    return true;
}

bool CliHelp::value_check(std::string const& varname, bool v, cli_def* cli) {
    return true;
}

bool CliHelp::value_check(std::string const& varname, float v, cli_def* cli) {
    return true;
}

bool CliHelp::value_check(std::string const& varname, std::string const& v, cli_def* cli) {

    std::regex match ("\\[[0-9]+\\]");
    std::string masked_varname  = std::regex_replace (varname, match, "[x]");

    _debug(cli, "value_check: varname = %s, value = %s", varname.c_str(), v.c_str());
    _debug(cli, "value_check:  masked = %s, value = %s", masked_varname.c_str(), v.c_str());

    auto cli_e = find(masked_varname);
    bool may_be_empty = true;

    bool value_filter_check = true;
    std::string value_filter_check_response;

    if(cli_e.has_value()) {
        may_be_empty = cli_e->get().may_be_empty();

        if(not v.empty()) {
            auto[ret, msg] = std::invoke(cli_e->get().value_filter(), v);
            value_filter_check = ret.has_value();
            value_filter_check_response = msg;

            _debug(cli, " CliElement value filter check : %d : '%s'", ret.has_value(), msg.c_str());
        }
    }


    // empty value check
    if(v.empty() and not may_be_empty) {
        _debug(cli, " ");
        _debug(cli, "this attribute cannot be empty");

        return false;
    }


    if(not value_filter_check) {

        cli_print(cli, "Value check failed: %s", value_filter_check_response.c_str());
        return false;
    }

    auto path_elems = string_split(masked_varname, '.');
    try {
        if (masked_varname.find("policy.[x]") == 0) {

            _debug(cli, "policy values check");

            // check policy
            if(path_elems[2] == "src" || path_elems[2] == "dst") {

                _debug(cli, "policy values for %s", path_elems[2].c_str());

                auto addrlist = CfgFactory::get().keys_of_db_address();
                if(std::find(addrlist.begin(), addrlist.end(), v) == addrlist.end()) {
                    _debug(cli, "policy values for %s: %s not found address db", path_elems[2].c_str(), v.c_str());
                    return false;
                }
            }
        }
        else {
        _debug(cli, "value_check: no specific check procedure programmed");
        }
    }
    catch(std::out_of_range const& e) {
        _debug(cli, "value_check: returning FAILED: out of range");
        return false;
    }

    _debug(cli, "value_check: returning OK");
    return true;
}


std::string CliHelp::help(help_type_t htype, const std::string& section, const std::string& key) {

    std::regex match ("\\[[0-9]+\\]");
    std::string masked_section  = std::regex_replace (section, match, "[x]");

    auto what = masked_section + "." + key;
    auto cli_e = find(what);

    if(not cli_e.has_value()) {
        std::regex remove_last_part("\\.[^.]+$");
        masked_section = std::regex_replace(section, remove_last_part, ".[x]");
        cli_e = find(masked_section + "." + key);
    }


    if(cli_e.has_value()) {
        if (htype == CliHelp::help_type_t::HELP_QMARK) {
            return cli_e->get().help_quick();
        } else {
            return cli_e->get().help();
        }
    }

    return std::string();
}