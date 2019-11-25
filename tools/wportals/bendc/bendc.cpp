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

#define MEM_NAME "/smithproxy_auth_ok"
#define MEM_SIZE 1024*1024
#define SEM_NAME "/smithproxy_auth_ok.sem"

#include <shmtable.hpp>




struct shm_logon_info {
    char  ip[4];
    char  username[64];
    char  groups[128];
};

struct login_token {
    char   token[64];
    char   url[512];
};

int main(void) {
    shared_table<shm_logon_info> b;
    b.attach(MEM_NAME,MEM_SIZE,SEM_NAME);

    printf("smithproxy shared memory tables analyzer:\n");
    printf("...\n");
    
    int i = 0;
    int ii = 0; // reload counter
    while(true) {
        b.acquire();
        if (b.read_header() < 0) {
	    printf("fatal: protocol error");
	}

	
	int loaded = b.load();
        b.release();
        
	if(loaded > 0) {
	    for(auto& li: b.entries()) {

		printf("%s: %16s \t groups: %s\n",inet_ntoa(*(in_addr*)li.ip),li.username,li.groups);
	    }
	}
	
        usleep(10000); // one milli
        
        if(ii > 1000)  { // reload each 10s
            printf("RELOAD!\n");
            b.dettach();
            
            bool r;
            do {
                r = b.attach(MEM_NAME,MEM_SIZE,SEM_NAME);
		if(! r) {
		  printf("Uggh. No data available!\n");
		  b.reset_seen_version(); // reset, reload db later
		  sleep(3);
		}
            } while(!r);
            
            ii = 0;
            
        }
        
        if(i > 100000) {
            break;
        }
        
        i++;
        ii++;
    }
    
    b.dettach();
}
