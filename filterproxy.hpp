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



#ifndef __FILTER_PROXY
 #define __FILTER_PROXY
 
#include <ctime>

#include <sobject.hpp>
#include <baseproxy.hpp>
#include <mitmproxy.hpp>

class MitmProxy;

class FilterProxy : public baseProxy, public socle::sobject {
public:
    
    FilterProxy(MitmProxy* parent);
    virtual ~FilterProxy() {};
    
    virtual std::string to_string(int verbosity=INF) { return std::string("filterProxy"); };
        
    DECLARE_C_NAME("filterProxy");
    DECLARE_LOGGING(to_string);
    
protected:
    MitmProxy* parent_;
};

// testing filter which triggers action after defined seconds
class TestFilter : public FilterProxy {
public:
    TestFilter(MitmProxy* parent, int seconds);
    virtual int handle_sockets_once(baseCom*);
    
    time_t trigger_at;
};

#endif //__FILTER_PROXY