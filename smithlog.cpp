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
    
*/

#include <display.hpp>
#include <smithlog.hpp>

int QueueLogger::write_log(unsigned int l, std::string& sss) {

    locked_guard<QueueLogger> ll(this);
    
    if(l <= level() ) {
        logs_.push(sss);
    }
    
    if(logs_.size() >= max_len) {
        logs_.pop();
        
    }
    
    // this is transitional code. It will be removed once queue picker is implemented
    if(logs_.size() > 0) {
        std::string msg = logs_.front(); logs_.pop();
        return logger::write_log(l, msg);
    }
    
    return 0;
}
