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


#include <filterproxy.hpp>
#include <mitmproxy.hpp>

DEFINE_LOGGING(FilterProxy);

FilterProxy::FilterProxy(MitmProxy* parent) : baseProxy(parent->com()->slave()), parent_(parent) {
    result_ = new FilterResult();
}





TestFilter::TestFilter(MitmProxy* parent, int seconds): FilterProxy(parent) {
    trigger_at = time(nullptr) + seconds;
}

int TestFilter::handle_sockets_once(baseCom* xcom) {
    
    if(time(nullptr) >= trigger_at) {
        counter++;
        trigger_at = time(nullptr) + 5;

        auto parent_name = [this](){ if(parent_) return parent_->to_string(iNOT); else return std::string("???"); };
        
        INF___("%s: filter triggered event counter %d", parent_name().c_str() ,counter);
    }
    
    return baseProxy::handle_sockets_once(xcom);
}
