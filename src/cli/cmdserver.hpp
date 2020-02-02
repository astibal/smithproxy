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

#ifndef _CMDSERVER_HPP_
   #define _CMDSERVER_HPP_

#include <libcli.h>

#include <cli/clihelp.hpp>


struct CliState {
    bool config_changed_flag = false;
    bool cli_debug_flag = false;

    int cli_port = 50000;
    int cli_port_base = 50000;
    std::string cli_enable_password;


    const char *debug_levels = "\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to level configured in config file";

    loglevel orig_ssl_loglevel = NON;
    loglevel orig_sslmitm_loglevel = NON;
    loglevel orig_sslca_loglevel = NON;

    loglevel orig_dns_insp_loglevel = NON;
    loglevel orig_dns_packet_loglevel = NON;

    loglevel orig_baseproxy_loglevel = NON;
    loglevel orig_epoll_loglevel = NON;
    loglevel orig_mitmproxy_loglevel = NON;
    loglevel orig_mitmmasterproxy_loglevel = NON;

    loglevel orig_mitmhostcx_loglevel = NON;
    loglevel orig_socksproxy_loglevel = NON;

    loglevel orig_auth_loglevel = NON;

    static CliState& get() {
        static CliState c;
        return c;
    }

    static CliHelp& help() {
        return get().help_;
    }

    CliState(CliState const&) = delete;
    CliState& operator=(CliState const&) = delete;

    using callback = int (*)(struct cli_def *,const char *,char * *,int);
    using set_callback = callback;
    using config_callback = callback;

    using callback_entry = std::tuple<unsigned int, set_callback, config_callback>;
    std::unordered_map<std::string, callback_entry> callback_map;

private:
    CliState() : help_(CliHelp::instance()) {};
    CliHelp& help_;
};

void cli_loop(unsigned short port=50000);

// SL_NONE - no filtering
// SL_IO_OSBUF_NZ - sessions with non-empty OS buffers, or non-empty smithproxy write buffers
// SL_IO_EMPTY - sessions with no data received and/or sent

typedef enum session_list_filter_flags { SL_NONE=0x0000 , SL_IO_OSBUF_NZ=0x0001 , SL_IO_EMPTY=0x0002 } session_list_filter_flags_t;
int cli_diag_proxy_session_list_extra(struct cli_def *cli, const char *command, char *argv[], int argc, int sl_flags);

#endif