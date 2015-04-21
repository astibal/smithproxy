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

#include <buffer.hpp>


class shared_buffer : public buffer {
protected:
    sem_t* semaphore = nullptr;
    std::string semaphore_name;
    std::string memory_name;
    int         memory_size;
    int         memory_fd;
public:
    shared_buffer() {}
    
    bool attach(const char* mem_name, const int mem_size, const char* sem_name) {
        semaphore_name = sem_name;
        memory_name = mem_name;
        memory_size = mem_size;
        
        unsigned char* shared_memory = nullptr;
        memory_fd  = -1;
        
        semaphore = sem_open(semaphore_name.c_str(),O_RDWR,0600);
        if(semaphore == nullptr) {
            printf("Getting a handle to the semaphore failed; errno is %d\n", errno);
            goto fail;
        }
        
        memory_fd = shm_open(memory_name.c_str(), O_RDWR, 0600);
        if(memory_fd  == -1) {
            printf("Couldn't get a handle to the shared memory; errno is %d\n", errno);
            goto fail;
        }
        
        shared_memory = (unsigned char*)mmap((void *)0, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, memory_fd, 0);
        if (shared_memory == MAP_FAILED) {
            printf("MMapping the shared memory failed; errno is %d\n", errno);
            goto fail;
        }
        

        data_ = shared_memory;
        capacity_ = mem_size;
        size_ = capacity_;
        free_ = 0;    // data cannot be detached
        
        return true;
        fail:
            
        return false;
    }
    
    bool dettach() {
        int rc = munmap(data_, (size_t)capacity_);
        if (rc) {
            printf("Unmapping the memory failed; errno is %d\n", errno);
        }        
        
        if(memory_fd > 0) {
            if (close(memory_fd) == -1) {
                printf("Closing memory's file descriptor failed; errno is %d\n", errno);
            }
        }
        
        rc = sem_close(semaphore);
        if (rc) {
            printf("Closing the semaphore failed; errno is %d\n", errno);
        }            
            
    }
    
    
    int release() {
        int rc = sem_post(semaphore);
        if(rc) {
            printf("Releasing the semaphore failed; errno is %d\n", errno);
        }
        
        return rc;
    }
    
    int acquire() {
        int rc = sem_wait(semaphore);

        if(rc) {
            printf("Acquiring the semaphore failed; errno is %d\n", errno);
        }
        
    }
};


#define MEM_NAME "/smithproxy_auth_ok"
#define MEM_SIZE 1024
#define SEM_NAME "/smithproxy_auth_ok.sem"

class bendc : public shared_buffer {
};


struct bend_header {
    unsigned int version;
    unsigned int entries;
    unsigned int row_size;
};

struct logon_info {
    char  ip[4];
    char  username[64];
    char  groups[128];
};

int main(void) {
    shared_buffer b;
    b.attach(MEM_NAME,MEM_SIZE,SEM_NAME);

    printf("smithproxy shared memory tables analyzer:\n");
    printf("...\n");
    
    int last_seen_version = 0;
    
    int i = 0;
    int ii = 0; // reload counter
    while(true) {
        b.acquire();
        bend_header* bh = (bend_header*)b.data();
        
        if(last_seen_version < bh->version) {
            
            last_seen_version = bh->version;
            printf("new table version available\n");

        
            printf("\"successfully authenticated users\" table:\n");
            printf("my row_size is %d\n",(int)sizeof(struct logon_info));
            printf("version %d: entries %d row_size: %d\n",bh->version, bh->entries,bh->row_size);
            
            if(sizeof(struct logon_info) != (long unsigned int)bh->row_size) {
                printf("Unexpected row size");
                break;
            } 
                
            unsigned char* records = &b.data()[sizeof(struct bend_header)];
            for (int n = 0 ; n < bh->entries ; n++) {
                logon_info* rec = (logon_info*)records;
                printf("%s: %s .. %s\n",inet_ntoa(*(in_addr*)rec->ip),rec->username,rec->groups);
                
                records+=sizeof(struct logon_info);
            }
        } else {
            //printf("same version %d:%d\n",last_seen_version,bh->version);
        }
        
        b.release();
        
        usleep(10000); // one milli
        
        if(ii > 1000)  { // reload each 10s
            printf("RELOAD!\n");
            b.detach();
            
            bool r;
            do {
                r = b.attach(MEM_NAME,MEM_SIZE,SEM_NAME);
                printf("Uggh. No data available!\n");
                sleep(3);
            } while(!r);
            
            ii = 0;
            last_seen_version = 0;
        }
        
        if(i > 100000) {
            break;
        }
        
        i++;
        ii++;
    }
    
    b.detach();
}
