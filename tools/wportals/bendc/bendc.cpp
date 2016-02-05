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
	    for(std::vector<shm_logon_info>::iterator i = b.entries().begin(); i != b.entries().end() ; ++i) {
		shm_logon_info& li = (*i);
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
