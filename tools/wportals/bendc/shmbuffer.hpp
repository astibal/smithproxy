
#ifndef SHMBUFFER_HPP
#define SHMBUFFER_HPP

#include <semaphore.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>

class shared_buffer {
protected:
    sem_t* semaphore = nullptr;
    std::string semaphore_name;
    std::string memory_name;
    int         memory_size;
    int         memory_fd;
    
    unsigned char* data_;
    unsigned int size_;
    unsigned int capacity_;
    
public:
    shared_buffer() {}

    unsigned char* data()    { return data_; }
    unsigned int   size()    { return size_; }
    unsigned int   capacity(){ return capacity_; }
    
    
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


#endif