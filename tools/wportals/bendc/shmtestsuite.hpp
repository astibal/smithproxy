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

#ifndef SHMTESTSUITE_HPP
 #define SHMTESTSUITE_HPP

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



/*
    This function will loop on the shared_table objects and print their content.
    
    It's called like this:
    
    
    // structure representing table row (RowType)
    struct logon_info {
        char  ip[4];
        char  username[64];
        char  groups[128];
        
        void hr() { printf("%s: %16s \t groups: %s\n",inet_ntoa(*(in_addr*)ip),username,groups); }
    };
    
    // generator returning RowType __by_value__.
    logon_token generator_to(int i) {
        logon_token t;

        int pid = getpid();    
        
        srand(time(nullptr));
        int ran = rand();
        memset(&t,0,sizeof(logon_info));

        snprintf(t.token,63,"%d-%010d",pid,ran);
        snprintf(t.url,512,"http://www.mag0.net/smithtest/%d/%010d.html",pid,ran);
        
        
        return t;
    }
    
    
    // ... 
    shared_table<logon_info> b;
    test_suite<shared_table<logon_info>,logon_info>(b,generator_li,I_MEM_NAME,I_MEM_SIZE,I_SEM_NAME);    
 */

template <class Shared_Buffer_Type,class RowType>
void test_suite(Shared_Buffer_Type& b, RowType (*generator)(int),const char* mem_name,unsigned int mem_size, const char* sem_name) {
    b.attach(mem_name,mem_size,sem_name);



    int i = 0;
    int ii = 0; // reload counter
    while(true) {
        b.acquire();
        if (b.read_header() < 0) {
            printf("fatal: protocol error\n");
            sleep(3);
            
            continue;
        }


        int loaded = b.load();
        int saved = 0;

        if(i % 1500 == 0) {
            RowType n = generator(i);
            b.entries().push_back(n);    
            b.save(true);
            
            saved = b.entries().size();
        }
            
        b.release();

        if(loaded > 0 or saved > 0) {
            if(saved > 0) {
                printf("New table pushed: version %d\n", b.seen_version());
            }
            for(typename std::vector<RowType>::iterator i = b.entries().begin(); i != b.entries().end() ; ++i) {
                RowType& rt = (*i);
                //printf("%s: %16s \t groups: %s\n",inet_ntoa(*(in_addr*)li.ip),li.username,li.groups);
                rt.hr();
            }
        }

        usleep(10000); // one milli

        if(ii > 1000)  { // reload each 10s
            printf("RELOAD!\n");
            b.dettach();

            bool r;
            do {
                r = b.attach(mem_name,mem_size,sem_name);
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


#endif