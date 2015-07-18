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

#ifndef ADDROBJ_HPP_
#define ADDROBJ_HPP_

#include <cidr.hpp>
#include <display.hpp>
#include <logger.hpp>

class AddressObject {
public:
    virtual bool match(CIDR* c) = 0;
    virtual std::string to_string() = 0;
    virtual ~AddressObject() {};
};


class CidrAddress : public AddressObject {
public:
    CidrAddress(CIDR* c) : c_(c) { }
    CIDR* cidr() { return c_; }

    int contains(CIDR *other);
    virtual bool match(CIDR* c) { return (contains(c) >= 0); };
    
    virtual std::string to_string() { char* temp = cidr_to_str(c_); std::string ret(temp); delete temp; return ret;  }
    
    
    virtual ~CidrAddress() { cidr_free(c_); };
protected:
    CIDR* c_;

DECLARE_C_NAME("CidrAddress");
};

#endif //ADDROBJ_HPP_