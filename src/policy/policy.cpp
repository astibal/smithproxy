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

#include <vars.hpp>
#include <policy/policy.hpp>

using namespace socle;

std::string PolicyRule::to_string(int verbosity) const {

    std::stringstream from;
    from << "PolicyRule: ";

    if(is_disabled) {
        from << " -- DISABLED -- ";
    }
    else if(cfg_err_is_disabled) {
        from << " -- ERR_DISABLED -- ";
    }
    else if(cfg_err_is_degraded) {
        from << " -- ERR_DEGRADED -- ";
    }


    switch(proto->value()) {
        case 6:
            from << "[tcp] ";
            break;
        case 17:
            from << "[udp] ";
            break;
        default:
            from << string_format(" [proto-%d] ", proto->value());
    }

    for(auto const& it: src) {

        from << "[";
        if(verbosity > iDIA) {
            from << string_format("(0x%x)", this);
        }
        from << it->value()->str() << "]";
    }
    from << ":";

    if(not src_ports.empty()) {
        for (auto const &it: src_ports) {
            if (it->value().first == 0 && it->value().second == 65535)
                from << "(*) ";
            else
                from << string_format("(%d,%d) ", it->value().first, it->value().second);
        }
    }
    else {
        from << "(*) ";
    }
    
    std::stringstream to;

    for(auto const& it: dst) {
        to << "[" << it->value()->str() << "]";
    }
    to << ":";

    if(not dst_ports.empty()) {
        for (auto const &it: dst_ports) {
            if (it->value().first == 0 && it->value().second == 65535)
                to << "(*) ";
            else
                to << string_format("(%d,%d) ", it->value().first, it->value().second);
        }
    }
    else {
        to << "(*) ";
    }
    
    std::stringstream out;
    out << from.str() << "-> " << to.str() << "= ";
    
    switch(action) {
        case POLICY_ACTION_PASS:
            out << "ACCEPT";
            break;
        case POLICY_ACTION_DENY:
            out << "REJECT";
            break;
        default:
            out << "???";
    }
    
    switch(nat) {
        case POLICY_NAT_NONE:
            out << "(nonat)";
            break;
        case POLICY_NAT_AUTO:
            out << "(iface)";
            break;
        case POLICY_NAT_POOL:
            out << "( pool)";
            break;
        default:
            out << "(  ?  )";
            break;
    }


    if(verbosity > iINF)
        out << " [" << std::to_string(cnt_matches) << "x]";
    
    out << ": ";

    auto print_profile = [&](const char* pref, auto const& sptr) {
        if(sptr) {
            out << string_format("\n    %s=%s", pref, sptr->element_name().c_str());

            // this would work only with debug builds where DEB is allowed
            if(verbosity > iDIA)
                out << string_format("  (0x%x) ",sptr.get());

        }
    };
    print_profile("auth", profile_auth);
    print_profile("tls", profile_tls);
    print_profile("det", profile_detection);
    print_profile("cont", profile_content);
    print_profile("alg_dns", profile_alg_dns);
    print_profile("routing", profile_routing);

    if(not features.empty()) {
        out << "\n    features=[ ";
        for(auto const& feat: features) {
            out << feat->value() << " ";
        }
        out << "]";
    }

    return out.str();
}


bool PolicyRule::match_addrgrp_cx(group_of_addresses const& sources, baseHostCX* cx) const {
    bool match = false;
    
     if(sources.empty()) {
         return true;
    }

    auto l = CidrAddress(cx->host());

    for(auto const& comp: sources) {

        if(comp->value()->match(l.cidr())) {
            _deb("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: matched", l.ip().c_str(), comp->value()->str().c_str());
            match = true;
            break;
        } else {
            _deb("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: not matched", l.ip().c_str(), comp->value()->str().c_str());
        }
    }

    return match;
}

bool PolicyRule::match_rangegrp_cx(group_of_ports const& ranges, baseHostCX* cx) const {
    bool match = false;
    
    if(ranges.empty()) {
        return  true;
    }

    int p = safe_val(cx->port());

    if(p < 0) return false;

    for(auto const& comp: ranges) {

        if((p >= comp->value().first) && (p <= comp->value().second)) {
            _deb("PolicyRule::match_rangergrp_cx: comparing %d with %s: matched", p, rangetos(comp->value()).c_str());
            match = true;
            break;
        } else {
            _deb("PolicyRule::match_rangergrp_cx: comparing %d with %s: not matched", p, rangetos(comp->value()).c_str());
        }
    }

    return match;
}

bool PolicyRule::match_rangegrp_vecx(group_of_ports const& ranges, std::vector<baseHostCX*> const& vecx) const {
    bool match = false;

    if(vecx.empty()) return true;

    int idx = -1;
    for(auto cx: vecx) {
        ++idx;

        match = match_rangegrp_cx(ranges, cx);
        if(match) {
            _deb("PolicyRule::match_rangegrp_vecx: %s matched (item idx %d)", cx->c_type(), idx);
            break;
        } else {
            _deb("PolicyRule::match_rangegrp_vecx: %s not matched", cx->c_type());
        }
    }
    
    return match;
}


bool PolicyRule::match_addrgrp_vecx(group_of_addresses const& sources, std::vector<baseHostCX*> const& vecx)  const{
    bool match = false;

    if(vecx.empty()) return true;

    int idx = -1;
    for(auto cx: vecx) {
        ++idx;

        match = match_addrgrp_cx(sources, cx);
        if(match) {
            _deb("PolicyRule::match_addrgrp_vecx: %s matched (item idx %d)", cx->c_type(), idx);
            break;
        } else {
            _deb("PolicyRule::match_addrgrp_vecx: %s not matched", cx->c_type());
        }
    }
    
    return match;
}

int PolicyRule::sock_2_net(int sock_type) const {
    switch (sock_type) {
        case SOCK_STREAM:
            return 6;
        case SOCK_DGRAM:
            return 17;
        default:
            return 0;
    }
}

bool PolicyRule::match_proto_cx(int acl_proto, const baseHostCX *cx) {

    bool ret = false;

    if( cx && cx->com()) {
        auto cx_proto = sock_2_net(cx->com()->l4_proto());
        if( cx_proto != 0) {
            if(acl_proto == cx_proto) {
                ret = true;
            }
        } else {
            throw std::logic_error("traffic cx cannot be matched due to unknown L4 protocol");
        }
    }
    return ret;
}



bool PolicyRule::match_proto_vecx(int acl_proto, std::vector<baseHostCX*> const& vec_cx) {

    if(vec_cx.empty()) return true;

    bool ret = false;
    for(auto cx: vec_cx) {
        if(match_proto_cx(acl_proto, cx)) {
            ret = true;
            continue;

        } else {
            ret = false;
            break;
        }
    }

    return ret;
}




bool PolicyRule::match(baseProxy* p) {
    
    bool lmatch = false;
    bool lpmatch = false;
    bool rmatch = false;
    bool rpmatch = false;

    if(is_disabled or cfg_err_is_disabled) {
        _dia("PolicyRule::match %s this policy is disabled", p->to_string(iINF).c_str());
        return false;
    }

    if(p != nullptr) {

        // compare if policy has proto match
        bool proto_match = false;

        if(proto->value() != 0) {
            proto_match = match_proto_vecx(proto->value(), p->ls()) && match_proto_vecx(proto->value(), p->lda());

        } else {
            // proto 0 means we don't care
            proto_match = true;

        }

        if(!proto_match) goto end;

        lmatch = match_addrgrp_vecx(src,p->ls()) && match_addrgrp_vecx(src,p->lda());
        if(!lmatch) goto end;

        lpmatch = match_rangegrp_vecx(src_ports,p->ls()) && match_rangegrp_vecx(src_ports,p->lda());
        if(!lpmatch) goto end;

        rmatch = match_addrgrp_vecx(dst,p->rs()) && match_addrgrp_vecx(dst,p->rda());
        if(!rmatch) goto end;

        rpmatch = match_rangegrp_vecx(dst_ports,p->rs()) && match_rangegrp_vecx(dst_ports,p->rda());
        if(!rpmatch) goto end;

        end:

        if (proto_match && lmatch && lpmatch && rmatch && rpmatch) {
            _inf("PolicyRule::match %s OK", p->to_string(iINF).c_str());
            cnt_matches++;

            return true;

        } else {
            _dia("PolicyRule::match %s FAILED: %d-%d:%d->%d:%d", p->to_string(iINF).c_str(), proto->value(), lmatch, lpmatch, rmatch, rpmatch);
        }

    } else {
        _err("PolicyRule::match: p is nullptr");
    }

    return false;
}

bool PolicyRule::match(std::vector<baseHostCX*>& l, std::vector<baseHostCX*>& r) {
    bool lmatch = false;
    bool lpmatch = false;
    bool rmatch = false;
    bool rpmatch = false;
    

    std::string ls("???");
    std::string rs("???");

    if(not l.empty() and l[0]) {
        ls = l[0]->str();
    }
    if(not r.empty() and r[0]) {
        rs = r[0]->str();
    }

    if(is_disabled or cfg_err_is_disabled) {
        _dia("PolicyRule::match_lr %s <+> %s - this policy is disabled", ls.c_str(), rs.c_str());
        return false;
    }

    // compare if policy has proto match
    bool proto_match = false;

    if(proto->value() != 0) {
        proto_match = match_proto_vecx(proto->value(), l);

    } else {
        // proto 0 means we don't care
        proto_match = true;

    }

    if(!proto_match) goto end;

    lmatch = match_addrgrp_vecx(src,l);
    if(!lmatch) goto end;

    lpmatch = match_rangegrp_vecx(src_ports,l);
    if(!lpmatch) goto end;

    rmatch = match_addrgrp_vecx(dst,r);
    if(!rmatch) goto end;

    rpmatch = match_rangegrp_vecx(dst_ports,r);
    if(!rpmatch) goto end;
    
    
    if(*log.level() >= DEB ) {
        for(auto i: l) _dum("PolicyRule::match_lr L: %s", i->str().c_str());
        for(auto i: r) _dum("PolicyRule::match_lr R: %s", i->str().c_str());
        _deb("PolicyRule::match_lr Success: %d-%d:%d->%d:%d", proto->value(), lmatch, lpmatch, rmatch, rpmatch);
    }

    end:

    if (proto_match && lmatch && lpmatch && rmatch && rpmatch) {
        _inf("PolicyRule::match_lr %s <+> %s OK", ls.c_str(), rs.c_str());
        cnt_matches++;
        
        return true;
    } else {
        _dia("PolicyRule::match_lr %s <+> %s FAILED: %d-%d:%d->%d:%d", ls.c_str(), rs.c_str(), proto->value(), lmatch, lpmatch, rmatch, rpmatch);
    }

    return false;
}


