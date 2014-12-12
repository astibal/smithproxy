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
    
*/    

#include <string>
#include <cstring>
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <cmdserver.hpp>
#include <cfgapi.hpp>
#include <socle.hpp>
#include <smithproxy.hpp>


void cmd_show_version(struct cli_def* cli) {

    cli_print(cli,"Smithproxy: %s%s",SMITH_VERSION,SMITH_DEVEL ? " -- !! development version !!" : "");
    cli_print(cli, "Socle     : %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " -- !! development version !!" : "");
}

int cli_show_version(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
    cmd_show_version(cli);
    return CLI_OK;
}

void cli_loop(short unsigned int port) {
    struct sockaddr_in servaddr;
    struct cli_command *c;
    struct cli_def *cli;
    int on = 1, x, s;

    // Must be called first to setup data structures
    cli = cli_init();

    // Set the hostname (shown in the the prompt)
    cli_set_hostname(cli, "smithproxy");

    // Set the greeting
    cli_set_banner(cli, "Smithproxy command line utility.");

    // Enable 2 username / password combinations
    cli_allow_user(cli, "admin", "");

    // Set up 2 commands "show counters" and "show junk"
    c = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
        cli_register_command(cli, c, "version", cli_show_version, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy version");

    // Create a socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Wait for a connection
    listen(s, 50);

    while ((x = accept(s, NULL, 0)))
    {
        // Pass the connection off to libcli
        cli_loop(cli, x);
        close(x);
    }

    // Free data structures
    cli_done(cli);

}