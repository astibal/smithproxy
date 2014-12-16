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
#include <thread>

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

#include <logger.hpp>
#include <cmdserver.hpp>
#include <cfgapi.hpp>
#include <socle.hpp>
#include <smithproxy.hpp>


static const char* debug_levels="set level to console:\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to level configured in config file";

void cmd_show_version(struct cli_def* cli) {
    
    cli_print(cli,":connected using socket %d",cli->client->_fileno);
    cli_print(cli,"Smithproxy: %s%s",SMITH_VERSION,SMITH_DEVEL ? " -- !! development version !!" : "");
    cli_print(cli, "Socle     : %s%s",SOCLE_VERSION,SOCLE_DEVEL ? " -- !! development version !!" : "");
}

int cli_show_version(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);

    
    cmd_show_version(cli);
    return CLI_OK;
}

int cli_debug_level(struct cli_def *cli, const char *command, char *argv[], int argc) {
    
    logger_profile* lp = lout.target_profiles()[(uint64_t)cli->client->_fileno];
    if(argc > 0) {
        
        std::string a1 = argv[0];

        if(a1 == "?") {
            cli_print(cli,"valid parameters: %s",debug_levels);
            lp->level_ = std::atoi(argv[0]);
            lout.level(lp->level_);
        } 
        else if(a1 == "reset") {
            lp->level_ = cfgapi_table.logging.cli_init_level;
            lout.level(cfgapi_table.logging.level);
        }
        else {
            //cli_print(cli, "called %s with %s, argc %d\r\n", __FUNCTION__, command, argc);
            lp->level_ = std::atoi(argv[0]);
            lout.level(lp->level_);
        }
    } else {
        
        cli_print(cli,"This cli debug level is set to: %d",lp->level_);
        cli_print(cli,"General logging level set to: %d",lout.level());
        for(auto i = lout.remote_targets().begin(); i != lout.remote_targets().end(); ++i) {
            cli_print(cli, "Logging level for: %s: %d",lout.target_name((uint64_t)(*i)),lout.target_profiles()[(uint64_t)(*i)]->level_);
        }
        for(auto i = lout.targets().begin(); i != lout.targets().end(); ++i) {
            cli_print(cli, "Logging level for: %s: %d",lout.target_name((uint64_t)(*i)),lout.target_profiles()[(uint64_t)(*i)]->level_);
        }        
    }
    
    return CLI_OK;
}


struct cli_ext : public cli_def {
    int socket;
};

void client_thread(int client_socket) {
        struct cli_command *show;
        struct cli_command *diag;
        
        struct cli_def *cli;

        // Must be called first to setup data structures
        cli = cli_init();

        // Set the hostname (shown in the the prompt)
        cli_set_hostname(cli, "smithproxy");

        // Set the greeting
        cli_set_banner(cli, "Smithproxy command line utility.");

        // Enable 2 username / password combinations
        cli_allow_user(cli, "admin", "");

        // Set up 2 commands "show counters" and "show junk"
        show  = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
            cli_register_command(cli, show, "version", cli_show_version, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "show smithproxy version");
        
        diag = cli_register_command(cli, NULL, "debug", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "diagnostic commands");
            cli_register_command(cli, diag, "level", cli_debug_level, PRIVILEGE_PRIVILEGED, MODE_EXEC, "set level of logging to this console");
        
        // Pass the connection off to libcli
        lout.remote_targets(string_format("cli-%d",client_socket),client_socket);

        logger_profile lp;
        lp.level_ = cfgapi_table.logging.cli_init_level;
        lout.target_profiles()[(uint64_t)client_socket] = &lp;
        
        cli_loop(cli, client_socket);
        
        lout.remote_targets().remove(client_socket);
        lout.target_profiles().erase(client_socket);
        close(client_socket);
        
        // Free data structures
        cli_done(cli);    
}

void cli_loop(short unsigned int port) {
    struct sockaddr_in servaddr;
    int on = 1;

    // Create a socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Wait for a connection
    listen(s, 50);

    int client_socket = 0;
    while ((client_socket = accept(s, NULL, 0)))
    {
        std::thread* n = new std::thread(client_thread,client_socket);
    }
}