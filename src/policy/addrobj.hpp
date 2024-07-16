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

#ifndef ADDROBJ_HPP_
#define ADDROBJ_HPP_

#include <utility>
#include <vars.hpp>

#include <ext/libcidr/cidr.hpp>
#include <display.hpp>
#include <log/logger.hpp>

#include <sobject.hpp>
#include <policy/profiles.hpp>
#include <policy/cfgelement.hpp>
#include <ranges.hpp>


class AddressObject : public socle::sobject, public CfgElement {
public:
    virtual bool match(cidr::CIDR* c) = 0;

    AddressObject() = default;
    ~AddressObject() override = default;


    struct log {
        static logan_lite const& policy() {
            static logan_lite l("policy.addr");
            return l;
        }
    };
    static inline logan_lite const& log = log::policy();
};


class CidrAddress : public AddressObject {
public:
    struct cidr_deleter {
        void operator()(cidr::CIDR*c) {
            _err("cidr freed!");
            cidr::cidr_free(c);
        }
    };
    using unique_cidr = std::unique_ptr<cidr::CIDR, cidr_deleter>;

    explicit CidrAddress(cidr::CIDR* c) : AddressObject(), c_(c) { }
    explicit CidrAddress(std::string const& v) : AddressObject(), c_(cidr::cidr_from_str(v.c_str())) {}

    cidr::CIDR* cidr() { return c_.get(); }
    std::string ip(int flags = CIDR_ONLYADDR) const {
        auto temp = raw::allocated(cidr_to_str(c_.get(), flags));
        std::string ret = string_format("%s", temp.value);

        return ret;
    }

    int contains(cidr::CIDR const* other) const;
    bool match(cidr::CIDR* c) override { return (contains(c) >= 0); };
    bool ask_destroy() override { return false; };

    std::string to_string(int verbosity) const override {
        auto temp = raw::allocated(cidr_to_str(c_.get()));

        std::string ret = string_format("Cidr: %s",temp.value);

        if(!element_name().empty() && verbosity > iINF) {
            ret += string_format(" (name=%s)", element_name().c_str());
        }

        return ret;
    }
    
private:
    unique_cidr c_;

TYPENAME_OVERRIDE("CidrAddress")
};

class DNS_Response;

class FqdnAddress : public AddressObject {
public:
    explicit FqdnAddress(std::string s) : AddressObject(), fqdn_(std::move(s)) { }
    std::string fqdn() const { return fqdn_; }
    std::shared_ptr<DNS_Response> find_dns_response(int cidr_type) const;
    
    bool match(cidr::CIDR* to_match) override;
    bool ask_destroy() override { return false; };

    std::string to_string(int verbosity) const override;

private:
    std::string fqdn_;

TYPENAME_OVERRIDE("FqdnAddress")
};

using CfgAddress = CfgSingle<std::shared_ptr<AddressObject>>;
using shared_CfgAddress =  std::shared_ptr<CfgAddress>;

#endif //ADDROBJ_HPP_