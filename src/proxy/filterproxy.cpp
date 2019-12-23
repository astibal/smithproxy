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


#include <proxy/filterproxy.hpp>
#include <proxy/mitmproxy.hpp>

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
        
        _inf("%s: filter triggered event counter %d", parent_name().c_str() ,counter);
    }
    
    return baseProxy::handle_sockets_once(xcom);
}
