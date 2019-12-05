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



#ifndef __FILTER_PROXY
 #define __FILTER_PROXY
 
#include <ctime>

#include <sobject.hpp>
#include <display.hpp>
#include <baseproxy.hpp>



struct FilterResult : public socle::sobject {
    // NONE - Send some data
    // WANT_MORE_LEFT -  asking for more LEFT bytes before we can FINISH
    // WANT_MORE_RIGHT - asking for more RIGHT bytes before we can FINISH
    // FINISHED_OK   - filtering has been finished. Don't send anything more. Proxy as needed.
    // FINISHED_DROP - filtering has been finished. Don't send anything more, data considered as harmful, drop parent proxy.
    typedef enum { NONE=0x0000, WANT_MORE_LEFT=0x0001, WANT_MORE_RIGHT=0x0002, FINISHED_DROP=0x4000, FINISHED_OK=0x8000 } status_flags;
    int status_ = NONE;
    
    
    bool is_flag(status_flags sf) { return flag_check<int>(&status_,(int)sf); };
    void set_flag(status_flags sf) { flag_set<int>(&status_,(int)sf); }
    
    lockbuffer left_in;   // what you read from left side of proxy (-> filtering will put it in right_out)
    lockbuffer left_out;  // what you should write to left side of proxy
    
    lockbuffer right_in;  // what you read on right side of proxy  (-> filtering will put it in left out)
    lockbuffer right_out; // what you should write to the right side of proxy
    
    std::string to_string(int verbosity=iINF) const override { static std::string r("FilterResult"); return r; };
    bool ask_destroy() override { return false; };
};

class MitmProxy;

class FilterProxy : public baseProxy, public socle::sobject {
public:
    
    FilterProxy(MitmProxy* parent);
    virtual ~FilterProxy() { if(result_) delete result_; };
    
    std::string to_string(int verbosity=iINF) const override { static std::string r("FilterProxy"); return r; };
    bool ask_destroy() override { return false; };
    
    FilterResult* result() { return result_; }
    
    DECLARE_C_NAME("FilterProxy");
    DECLARE_LOGGING(to_string);
    
protected:
    MitmProxy* parent_{};
    FilterResult* result_{};
    
    
};

// testing filter which triggers action after defined seconds
class TestFilter : public FilterProxy {
public:
    TestFilter(MitmProxy* parent, int seconds);
    virtual int handle_sockets_once(baseCom*);
    
    
    time_t trigger_at;
    int counter = 0;
private:
    logan_attached<TestFilter> log = logan_attached<TestFilter>(this, "proxy");
};

#endif //__FILTER_PROXY