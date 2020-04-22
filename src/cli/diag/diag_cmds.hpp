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

#ifndef SMITHPROXY_DIAG_CMDS_HPP
#define SMITHPROXY_DIAG_CMDS_HPP

#include <libcli.h>

int cli_diag_ssl_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_cache_print(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_ssl_wl_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_wl_clear(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_wl_stats(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_ssl_crl_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_crl_stats(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_ssl_verify_clear(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_verify_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_verify_stats(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_ssl_ticket_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_ticket_stats(struct cli_def *cli, const char *command, char *argv[], int argc);


#ifndef USE_OPENSSL11
int cli_diag_ssl_memcheck_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_memcheck_enable(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_ssl_memcheck_disable(struct cli_def *cli, const char *command, char *argv[], int argc);
#endif

int cli_diag_ssl_ca_reload(struct cli_def *cli, const char *command, char *argv[], int argc);


int cli_diag_dns_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_dns_cache_stats(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_dns_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_dns_domain_cache_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_dns_domain_cache_clear(struct cli_def *cli, const char *command, char *argv[], int argc);


int cli_diag_identity_ip_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_identity_ip_clear(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_writer_stats(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_mem_buffers_stats(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_mem_objects_stats(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_mem_trace_mark (struct cli_def *cli, const char *command, char **argv, int argc);

int cli_diag_mem_trace_list (struct cli_def *cli, const char *command, char **argv, int argc);
int cli_diag_mem_objects_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_mem_objects_search(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_mem_objects_clear(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_proxy_session_list(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_proxy_session_io_list(struct cli_def *cli, const char *command, char *argv[], int argc);

int cli_diag_proxy_session_list_extra(struct cli_def *cli, const char *command, char *argv[], int argc, int sl_flags);
int cli_diag_proxy_session_clear(struct cli_def *cli, const char *command, char *argv[], int argc);
int cli_diag_proxy_policy_list(struct cli_def *cli, const char *command, char *argv[], int argc);


int cli_diag_sig_list(struct cli_def *cli, const char *command, char *argv[], int argc);
bool register_diags(cli_def* cli, cli_command* diag);


#endif //SMITHPROXY_DIAG_CMDS_HPP
