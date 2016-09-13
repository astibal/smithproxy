#ifndef _STATICCONTENT_HPP
 #define _STATICCONTENT_HPP

#include <sobject.hpp>
#include <ptr_cache.hpp>
#include <nltemplate.hpp>

using namespace ext::nltemplate;

class StaticContent : public socle::sobject {

protected:
    ptr_cache<std::string,Template>* templates_;
    
public:
    StaticContent() : socle::sobject::sobject() { templates_ = new ptr_cache<std::string,Template> ("replacement message cache"); };
    virtual ~StaticContent() { templates_->invalidate(); delete templates_; };
    virtual bool ask_destroy() { return false; };
    virtual std::string to_string(int verbosity=INF) { return std::string("StaticContent"); };

    bool load_files(std::string& dir);
    
    std::string render_noargs(std::string s);
    std::string render_msg_test();
    std::string render_msg_html_page(std::string& caption, std::string& meta, std::string& content,const char* window_width="300px");
    Template* get(std::string s);
    
    DECLARE_C_NAME("StaticContent");
    DECLARE_LOGGING(to_string);  
};


extern StaticContent* global_staticconent;
#endif