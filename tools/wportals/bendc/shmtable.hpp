#ifndef SHMTABLE_HPP
#define SHMTABLE_HPP


#include <vector>
#include <shmbuffer.hpp>

struct shared_table_header {
    unsigned int version;
    unsigned int entries;
    unsigned int row_size;
};

template<class RowType>
class shared_table : public shared_buffer {

public:  
  shared_table() {
      header_size = sizeof(struct shared_table_header);
      row_size = sizeof(RowType);
      memset(&cur_data_header,0,sizeof(struct shared_table_header));
  };
  virtual ~shared_table() {}
  
  int read_header() {
      shared_table_header* bh = (shared_table_header*)data();
      cur_data_header = *bh;
      
      if(sizeof(RowType) != (long unsigned int)header_rowsize()) {
	  return -1;
      }       
      
      return bh->version;
  }
  int header_version() { return cur_data_header.version; }
  int header_entries() { return cur_data_header.entries; }
  int header_rowsize() { return cur_data_header.row_size; }
  void reset_seen_version() { seen_version_ = 0; }
  int seen_version()   { return seen_version_; } 
  void seen_version(int i)   { seen_version_ = i; } 
  
  std::vector<RowType>& entries() { return entries_; }

  int load() {
    
        if(seen_version() < header_version() || ( header_version() == 0 && seen_version() > 0)) {
            
	    on_new_version(seen_version(),header_version());
	    //entries().clear();
            seen_version(header_version());
	    
	    
            printf("new table version available: %d\n",header_version());
//             printf("\"successfully authenticated users\" table:\n");
//             printf("my row_size is %d\n",(int)sizeof(struct logon_info));
//             printf("version %d: entries %d row_size: %d\n",header_version(), header_entries(),header_rowsize());

            unsigned char* records = &data()[sizeof(struct shared_table_header)];
            for (int n = 0 ; n < header_entries() ; n++) {
                RowType* rec = (RowType*)records;
                //printf("%s: %16s \t groups: %s\n",inet_ntoa(*(in_addr*)rec->ip),rec->username,rec->groups);
		
		on_new_entry(rec);
		//entries().push_back(*rec);
                
                records+=sizeof(RowType);
            }
            
            on_new_finished();
            return entries().size();
        } else {
            //printf("same version %d:%d\n",seen_version_,header_version());
        }    
        
        return 0;
  }

  virtual void on_new_version(int o, int n) {
      entries().clear();
  }
  virtual void on_new_entry(RowType* r) {
      entries().push_back(*r);
  }
  
  virtual void on_new_finished() {}
  
  
protected:
    int version = 0;
    int header_size = 0;
    int row_size = 0;

    std::vector<RowType> entries_;
    int seen_version_ = 0;
    
private:
    shared_table_header cur_data_header;
};


#endif