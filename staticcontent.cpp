#include <staticcontent.hpp>

DEFINE_LOGGING(StaticContent);

StaticContent* global_staticconent;


bool StaticContent::load_files(std::string& dir) {
    bool ret = true;
    
    try {
        LoaderFile loader_file;
        std::vector<std::string> names;
        
        names.push_back("test");
        
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

std::string StaticContent::render_noargs(std::string& name) {

    Template* t = templates_->get(name);
    if(t) {
        return t->render();
    } else {
        ERR___("cannot load template '%s'",name.c_str())
    }
    
    return "";
}
