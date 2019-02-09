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


#ifndef _LOADB_HPP_
#define _LOADB_HPP_

#include <string>
#include <vector>
#include <map>
#include <set>

#include <hostcx.hpp>
#include <lockable.hpp>


struct HostInfo {
    HostInfo() : host() {};
    HostInfo(Host h) : host(h) {};
    
    // host ip:port information
    Host host;
    
    // number of uses. It's responsibility of callers to update this counter
    unsigned int hits{0};
    
    // should this HostsInfo be used? Very important variable. Adds/Removes itself with this from HostPool candidates.
    bool is_active{true};
};

//
// HostPool is a generic class maintaining usable Host for various purposes. 
// Loadbalancing is best example. But it can serve also IP address pool, or server active/passive tracking.
// 
// It utilizes hashtable(host) --> HostInfo
// 
// Because mapped HostInfo stores state data and also UP/DOWN indicator, for exact calculation of selecting
// correct host we need to maintain also candidate list.
// So if state of Host (in HostInfo) is changed, is responsibility of user to call refresh() to recompute 
// candidates.


template <class HostInfoType>
class HostPool : public lockable {
public:
    HostPool();
    virtual ~HostPool();
    
    // insert new entry into a list of available Hosts, unless the key is already there. Return false if so.
    bool insert_new(Host h);
    // calculate winner, and get me his HostInfo 
    virtual const HostInfoType* compute();
    // recalculate candidates. Needed if you insert host, or if state of any inserted host changes. 
    virtual void refresh();
    
    
    virtual int compute_index() = 0;
    
protected:
    
    // full list of possible candidates, including down candidates, or disabled candidates.
    std::unordered_map<Host,HostInfoType*> host_data_;
    
    // list of active and up candidates. This vector is used by compute to 
    std::vector<HostInfoType*> candidates;
};


#endif