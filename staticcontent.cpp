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

#include <staticcontent.hpp>

bool StaticContent::load_files(std::string& dir) {
    bool ret = true;
    
    try {
        LoaderFile loader_file;
        std::vector<std::string> names;

        for(const std::string& name: { "test", "html_page", "html_img_warning"} ) {
            auto* t_temp = new Template(loader_file);
            t_temp->load(dir + name + ".txt");
            templates_->set(name,t_temp);
        }
    }
    catch(std::exception& e) {
        ret = false;
    }
    
    return ret;
}

Template* StaticContent::get(std::string const& name) {
    Template* t = templates_->get(name);
    if(!t) {
        ERR_("StaticContent::get: cannot load template '%s'",name.c_str())
    }

    return t;
}


std::string StaticContent::render_noargs(std::string const& name) {

    Template* t = get(name);
    if(t) {
        return t->render();
    } 
    
    return "";
}

std::string StaticContent::render_server_response(std::string& message, unsigned int code) {
    std::stringstream out;
    out << string_format("HTTP/1.1 %3d OK\r\n",code);
    out << "Server: Smithproxy/1.1\r\n";
    out << "Content-Type: text/html\r\n";
    out << "Content-Length: " + std::to_string(message.length()); out << "\r\n";
    
    out << "\r\n";
    out << message;
    
    return out.str();
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
