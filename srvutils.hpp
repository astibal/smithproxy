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

#ifndef SRVUTILS_HPP_
#define SRVUTILS_HPP_
 

template <class Listener, class Com>
Listener* prepare_listener(std::string& str_port,const char* friendly_name,int def_port,int sub_workers) {
    
    if(sub_workers < 0) {
        return nullptr;
    }
    
    int port = def_port;
    
    if(str_port.size()) {
        try {
         port = std::stoi(str_port);
        }
        catch(std::invalid_argument e) {
            ERR_("Invalid port specified: %s",str_port.c_str());
            return NULL;
        }
    }
    
    NOT_("Entering %s mode on port %d",friendly_name,port);
    auto s_p = new Listener(new Com());
    s_p->com()->nonlocal_dst(true);
    s_p->worker_count_preference(sub_workers);

    // bind with master proxy (.. and create child proxies for new connections)
    int s = s_p->bind(port,'L');
    if (s < 0) {
        FAT_("Error binding %s port (%d), exiting",friendly_name,s);
        delete s_p;
        return NULL;
    };
    s_p->com()->unblock(s);
    
    s_p->com()->set_monitor(s);
    s_p->com()->set_poll_handler(s,s_p);
    
    return s_p;
}

template <class Listener, class Com>
Listener* prepare_listener(std::string& str_path,const char* friendly_name,std::string def_path,int sub_workers) {
    
    if(sub_workers < 0) {
        return nullptr;
    }
    
    std::string path = str_path;
    if( path.size() == 0 ) {
        path = def_path;
    }
    
    NOT_("Entering %s mode on port %s",friendly_name,path.c_str());
    auto s_p = new Listener(new Com());
    s_p->com()->nonlocal_dst(true);
    s_p->worker_count_preference(sub_workers);

    // bind with master proxy (.. and create child proxies for new connections)
    int s = s_p->bind(path.c_str(),'L');
    if (s < 0) {
        FAT_("Error binding %s port (%d), exiting",friendly_name,s);
        delete s_p;
        return NULL;
    };
    
    return s_p;
}


#endif