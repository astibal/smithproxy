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

#include <policy/inspectors.hpp>
#include <proxy/mitmhost.hpp>

std::string Inspector::remove_redundant_dots(std::string orig) {
    std::string norm;  

    int dot_mark = 1;
    for(unsigned int i = 0; i < orig.size(); i++) {
        if(orig[i] == '.') {
            if(dot_mark > 0) continue;
            
            norm +=orig[i];
            dot_mark++;
        } else {
            dot_mark = 0;
            norm +=orig[i];
        }
    }
    if(dot_mark > 0) {
        norm = norm.substr(0,norm.size()-dot_mark);
    }
    
    return norm;
}

std::vector< std::string > Inspector::split(std::string str, unsigned char delimiter) {
    std::vector<std::string> ret;
    
    bool empty_back = true;
    for(unsigned int i = 0; i < str.size() ; i++) {
        if(i == 0)
            ret.push_back("");
            
        if(str[i] == delimiter) {
            
            if(ret.size() > 0)
                if(ret.back().size() == 0) ret.pop_back();

            ret.push_back("");
            empty_back = true;
        } else {
            ret.back()+= str[i];
            empty_back = false;
        }
    }
    
    if(empty_back) {
        ret.pop_back();
    }
    
    return ret;    
}

std::pair<std::string,std::string> Inspector::split_fqdn_subdomain(std::string& fqdn) {
        std::string topdom;
        std::string subdom;
        std::vector<std::string> dotted_fqdn = split(fqdn,'.');
        
        if(dotted_fqdn.size() > 2 ) {
            
            unsigned int  i = 1;
            for(auto it = dotted_fqdn.begin(); it != dotted_fqdn.end(); ++it) {
                if(i <= dotted_fqdn.size() - 2) {
                    subdom += *it;
                    
                    if(i < dotted_fqdn.size() - 2) {
                        subdom += ".";
                    }
                } else {
                    topdom += *it;
                    if(i < dotted_fqdn.size()) {
                        topdom += ".";
                    }
                }
                
                i++;
            }
        }
        
        return std::pair<std::string,std::string>(topdom,subdom);
}

