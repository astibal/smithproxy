#ifndef _STATICCONTENT_HPP
 #define _STATICCONTENT_HPP

#include <sobject.hpp>

class StaticContent : public socle::sobject {

public:
    virtual bool ask_destroy() { return false; };
    virtual std::string to_string(int verbosity=INF) { return std::string("StaticContent"); };
        
    DECLARE_C_NAME("StaticContent");
    DECLARE_LOGGING(to_string);  
};


extern StaticContent global_staticconent;
#endif