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

#include <basecom.hpp>
#include <tcpcom.hpp>
#include <dns.hpp>
#include <signature.hpp>
#include <apphostcx.hpp>

class Inspector {
public:
    virtual ~Inspector() {}
    virtual void update(AppHostCX* cx) = 0;
    
    inline bool completed() const   { return completed_; }
    inline bool in_progress() const { return in_progress_; }
    inline bool result() const { return result_; }

protected:
    bool completed_ = false;
    void completed(bool b) { completed_ = b; }
    bool in_progress_ = false;
    void in_progress(bool b) { in_progress_ = b; }
    bool result_ = false;
    void result(bool b) { result_ = b; }
    
    int stage = 0;
};


class DNS_Inspector : public Inspector {
public:
    virtual ~DNS_Inspector() {};  
    virtual void update(AppHostCX* cx);
private:
    bool is_tcp = false;

    DNS_Request req_;
    DNS_Response resp_;
};