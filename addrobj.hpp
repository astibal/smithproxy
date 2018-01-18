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
#include <sobject.hpp>

class AddressObject : public socle::sobject {
public:
    virtual bool match(CIDR* c) = 0;
    virtual std::string to_string(int=iINF) = 0;
    virtual ~AddressObject() {};
};


class CidrAddress : public AddressObject {
public:
    CidrAddress(CIDR* c) : c_(c) { }
    CIDR* cidr() { return c_; }

    int contains(CIDR *other);
    virtual bool match(CIDR* c) { return (contains(c) >= 0); };
    virtual bool ask_destroy() { return false; };
    
    virtual std::string to_string(int verbosity=iINF) { char* temp = cidr_to_str(c_); std::string ret = string_format("CidrAddress: %s",temp); delete temp; return ret;  }
    
    
    virtual ~CidrAddress() { cidr_free(c_); };
protected:
    CIDR* c_;

DECLARE_C_NAME("CidrAddress");
};

class FqdnAddress : public AddressObject {
public:
    FqdnAddress(std::string s) : fqdn_(s) { }
    virtual bool match(CIDR* c);
    virtual bool ask_destroy() { return false; };
    virtual std::string to_string(int verbosity=iINF);
protected:
    std::string fqdn_;

DECLARE_C_NAME("FqdnAddress");
};

#endif //ADDROBJ_HPP_