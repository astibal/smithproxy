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

/*
 *  Compile and link:
 *  g++ -I. -I ../../../../socle/common/ shmtest.cpp -std=c++11 -o shmtest -pthread -lrt
 */

#include <cstdio> 
#include <cerrno> 
#include <unistd.h> 
#include <cstring> 
#include <ctime>


#include <semaphore.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#define I_MEM_NAME "/smithproxy_auth_ok"
#define I_MEM_SIZE 1024*1024
#define I_SEM_NAME "/smithproxy_auth_ok.sem"


#define T_MEM_NAME "/smithproxy_auth_token"
#define T_MEM_SIZE I_MEM_SIZE
#define T_SEM_NAME "/smithproxy_auth_token.sem"

#include <shmtable.hpp>
#include <shmtestsuite.hpp>
#include <shmauth.hpp>


shm_logon_info generator_li(int i) {
    
    shm_logon_info n;
    int pid = getpid();            
    memset(&n,0,sizeof(shm_logon_info));
    
    inet_aton("192.168.1.1",(in_addr*)&n.ip);
    snprintf(n.username,63,"astib_%d_%d",pid,i);
    strcpy(n.groups,"some_groups");
    
    return n;
}

shm_logon_token generator_to(int i) {
    shm_logon_token t;

    int pid = getpid();    
    
    srand(time(nullptr));
    int ran = rand();
    memset(&t,0,sizeof(shm_logon_info));

    snprintf(t.token,63,"%d-%010d",pid,ran);
    snprintf(t.url,512,"http://www.mag0.net/smithtest/%d/%010d.html",pid,ran);
    
    
    return t;
}



void help() {
    printf("Usage: shmtest <logon|token>\n");
}


int main(int argc, char** argv) {
    printf("smithproxy shared memory tables analyzer:\n");
    printf("...\n");    

    
    if(argc > 1) {
        std::string a(argv[1]);
        
        if(a == "logon") {
            shared_table<shm_logon_info> b;
            test_suite<shared_table<shm_logon_info>,shm_logon_info>(b,generator_li,I_MEM_NAME,I_MEM_SIZE,I_SEM_NAME);
        } 
        else if (a == "token") {
            shared_table<shm_logon_token> b;
            test_suite<shared_table<shm_logon_token>,shm_logon_token>(b,generator_to,T_MEM_NAME,T_MEM_SIZE,T_SEM_NAME);
        }
    } 

    help();
}
