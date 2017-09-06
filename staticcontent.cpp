#include <staticcontent.hpp>

DEFINE_LOGGING(StaticContent);

StaticContent* global_staticconent;


bool StaticContent::load_files(std::string& dir) {
    bool ret = true;
    
    try {
        LoaderFile loader_file;
        std::vector<std::string> names;
        
        names.push_back("test");
        names.push_back("html_page");
        
        names.push_back("html_img_warning");
        
        for(std::string& name: names) {
            Template* t_temp = new Template(loader_file);
            t_temp->load(dir + name + ".txt");
            templates_->set(name,t_temp);
        }
    }
    catch(std::exception& e) {
        ret = false;
    }
    
    return ret;
}

Template* StaticContent::get(std::string name) {
    Template* t = templates_->get(name);
    if(!t) {
        ERR___("cannot load template '%s'",name.c_str())
    }
    
    return t;
}


std::string StaticContent::render_noargs(std::string name) {

    Template* t = get(name);
    if(t) {
        return t->render();
    } 
    
    return "";
}

std::string StaticContent::render_server_response(std::string& message) {
    std::string out;
    out += "HTTP/1.1 OK\r\n";
    out += "Server: Smithproxy/1.1\r\n";
    out += "Content-Type: text/html\r\n";
    out += "Content-Length: " + std::to_string(message.length()); out += "\r\n";
    
    out += "\r\n";
    out += message;
    out += "\r\n";
    
    return out;
}

std::string StaticContent::render_msg_html_page(std::string& caption, std::string& meta, std::string& content, const char* window_width) {
    Template* t = get("html_page");
    t->set("title",caption);
    t->set("meta",meta);
    t->set("message",content);
    t->set("window_width",window_width);
    
    std::string r = t->render();
    return r;
}
