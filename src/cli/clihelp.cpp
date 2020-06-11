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

#include <libcli.h>

#include <cli/clihelp.hpp>
#include <cli/cligen.hpp>
#include <common/log/logan.hpp>
#include <cfgapi.hpp>

void CliHelp::init() {
    help_add("default","");
    help_add("settings.certs_path", "directory for TLS-resigning CA certificate and key");
    help_add("settings.certs_ca_key_password","TLS-resigning CA private key protection password");
    help_add("settings.ca_bundle_path", "trusted CA store path (to verify server-side connections)");
    help_add("settings.plaintext_port", "base divert port for non-SSL TCP traffic");
    help_add("settings.plaintext_workers", "non-SSL TCP traffic worker thread count");
    help_add("settings.ssl_port", "base divert port for SSL TCP traffic");
    help_add("settings.ssl_workers", "SSL TCP traffic worker thread count");
    help_add("settings.ssl_autodetect", "Detect TLS ClientHello on unusual ports");
    help_add("settings.ssl_autodetect_harder", "Detect TSL ClientHello - wait a bit longer");
    help_add("settings.ssl_ocsp_status_ttl", "hardcoded TTL for OCSP response validity");
    help_add("settings.ssl_crl_status_ttl", "hardcoded TTL for downloaded CRL files");
    help_add("settings.udp_port", "base divert port for non-DTLS UDP traffic");
    help_add("settings.udp_workers", "non-DTLS traffic worker thread count");
    help_add("settings.dtls_port", "base divert port for DTLS UDP traffic");
    help_add("settings.dtls_workers", "DTLS traffic worker thread count");
    help_add("settings.socks_port", "base SOCKS proxy listening port");
    help_add("settings.socks_workers", "SOCKS proxy traffic thread count");
    help_add("settings.log_level", "file logging verbosity level");
    help_add("settings.log_file", "log file");
    help_add("settings.log_console", "toggle logging to standard output");
    help_add("settings.syslog_server", "IP address of syslog server");
    help_add("settings.syslog_port", "syslog server port");
    help_add("settings.syslog_facility", "syslog facility");
    help_add("settings.syslog_level", "syslog logging verbosity level");
    help_add("settings.syslog_family", "IPv4 or IPv6?");
    help_add("settings.sslkeylog_file", "where to dump TLS keying material");
    help_add("settings.messages_dir", "replacement text directory");
    help_add("settings.write_payload_dir", "root directory for packet dumps");
    help_add("settings.write_payload_file_prefix", "packet dumps file prefix");
    help_add("settings.write_payload_file_suffix", "packet dumps file suffix");
    help_add("settings.auth_portal", "** configure authentication portal settings");
    help_add("settings.cli", "** configure CLI specific settings");
    help_add("settings.socks", "** configure SOCKS specific settings");


    qmark_add("default", "enter <value>");
    qmark_add("settings.certs_path", "<string> with path to a directory");
    qmark_add("settings.certs_ca_key_password","");
    qmark_add("settings.ca_bundle_path", "");
    qmark_add("settings.plaintext_port", "");
    qmark_add("settings.plaintext_workers", "");
    qmark_add("settings.ssl_port", "");
    qmark_add("settings.ssl_workers", "");
    qmark_add("settings.ssl_autodetect", "");
    qmark_add("settings.ssl_autodetect_harder", "");
    qmark_add("settings.ssl_ocsp_status_ttl", "");
    qmark_add("settings.ssl_crl_status_ttl", "");
    qmark_add("settings.udp_port", "");
    qmark_add("settings.udp_workers", "");
    qmark_add("settings.dtls_port", "");
    qmark_add("settings.dtls_workers", "");
    qmark_add("settings.socks_port", "");
    qmark_add("settings.socks_workers", "");
    qmark_add("settings.log_level", "");
    qmark_add("settings.log_file", "");
    qmark_add("settings.log_console", "");
    qmark_add("settings.syslog_server", "");
    qmark_add("settings.syslog_port", "");
    qmark_add("settings.syslog_facility", "");
    qmark_add("settings.syslog_level", "");
    qmark_add("settings.syslog_family", "");
    qmark_add("settings.sslkeylog_file", "");
    qmark_add("settings.messages_dir", "");
    qmark_add("settings.write_payload_dir", "");
    qmark_add("settings.write_payload_file_prefix", "");
    qmark_add("settings.write_payload_file_suffix", "");
    qmark_add("settings.auth_portal", "");
    qmark_add("settings.cli", "");
    qmark_add("settings.socks", "");

    qmark_add("debug.log_data_crc","calculate received CRC data (helps to identify proxy bugs)");

    qmark_add("proto_objects", "IP protocols");
    qmark_add("proto_objects.[0].id", "IP protocol number (tcp=6, udp=17)");
    qmark_add("port_objects", "TCP/UDP ports");

    qmark_add("port_objects[0].start", "port range start");
    qmark_add("port_objects[0].end", "port range end");

    qmark_add("policy.[0].proto", "protocol to match (see proto_objects)");
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

    _debug(cli, "value_check: varname = %s, value = %s", varname.c_str(), v.c_str());

    auto path_elems = string_split(varname, '.');
    try {
        if (varname.find("policy.[") == 0) {

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