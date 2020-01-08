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

#include <policy/policy.hpp>

DEFINE_LOGGING(PolicyRule);

std::string PolicyRule::to_string(int verbosity) const {

    std::stringstream from;
    from << "PolicyRule:";
    
    switch(proto) {
        case 6:
            from << " [tcp] ";
            break;
        case 17:
            from << " [udp] ";
            break;
        default:
            from << string_format(" [%3d] ",proto);
    }
    
    if(src_default) from << "*";
    for(auto it: src) {
        if(verbosity > iINF) {
            from << string_format("(0x%x)",this);
        }
        from << it->to_string() << " ";
    }
    from << ":";
    if(src_ports_default) from << "*";
    for(auto it: src_ports) {
        if(it.first == 0 && it.second == 65535)
            from << "(*) ";
        else
            from << string_format("(%d,%d) ",it.first,it.second);
    }
    
    std::stringstream to;

    if(dst_default) to << "*";
    for(auto it: dst) {
        to << it->to_string() << " ";
    }
    to << ":";
    if(dst_ports_default) to << "*";
    for(auto it: dst_ports) {
        if(it.first == 0 && it.second == 65535)
            to << "(*) ";
        else
            to << string_format("(%d,%d) ",it.first,it.second);
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
    
    if(verbosity > INF) {
        out << ": ";
        if(profile_auth) out << string_format("\n    auth=%s  (0x%x) ",profile_auth->prof_name.c_str(),profile_auth);
        if(profile_tls) out << string_format("\n    tls=%s  (0x%x) ",profile_tls->prof_name.c_str(),profile_tls);
        if(profile_detection) out << string_format("\n    det=%s  (0x%x) ",profile_detection->prof_name.c_str(),profile_detection);
        if(profile_content) out << string_format("\n    cont=%s  (0x%x) ",profile_content->prof_name.c_str(),profile_content);
        if(profile_alg_dns) out << string_format("\n    alg_dns=%s  (0x%x) ",profile_alg_dns->prof_name.c_str(),profile_alg_dns);
    }
    
    return out.str();
}


bool PolicyRule::match_addrgrp_cx(std::vector<std::shared_ptr<AddressObject>> &sources, baseHostCX* cx) {
    bool match = false;
    
    if(sources.empty()) {
        match = true;
//                 _dia("PolicyRule: matched ");
    } else {
        CIDR* l = cidr_from_str(cx->host().c_str());
        for(auto comp: sources) {
            
            if(comp->match(l)) {
                if(*log.level() >= DIA) {
                    char* a = cidr_to_str(l);
                    _deb("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: matched", a, comp->to_string().c_str());
                    free(a);
                }
                match = true;
                break;
            } else {
                if(*log.level() >= DIA) {
                    char* a = cidr_to_str(l);
                    _deb("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: not matched", a, comp->to_string().c_str());
                    free(a);
                }
            }
        }
        cidr_free(l);
    }

    return match;
}

bool PolicyRule::match_rangegrp_cx(std::vector< range >& ranges, baseHostCX* cx) {
    bool match = false;
    
    if(ranges.empty()) {
        match = true;
//                 _dia("PolicyRule: matched ");
    } else {
        int p = std::stoi(cx->port());
        for(auto const& comp: ranges) {

            if((p >= comp.first) && (p <= comp.second)) {
                _deb("PolicyRule::match_rangergrp_cx: comparing %d with %s: matched",p,rangetos(comp).c_str());
                match = true;
                break;
            } else {
                _deb("PolicyRule::match_rangergrp_cx: comapring %d with %s: not matched",p,rangetos(comp).c_str());
            }
        }
    }

    return match;
}

bool PolicyRule::match_rangegrp_vecx(std::vector< range >& ranges, std::vector< baseHostCX* >& vecx) {
    bool match = false;
    
    int idx = -1;
    for(auto cx: vecx) {
        ++idx;

        match = match_rangegrp_cx(ranges, cx);
        if(match) {
            _deb("PolicyRule::match_rangegrp_vecx: %s matched", cx->c_name());
            break;
        } else {
            _deb("PolicyRule::match_rangegrp_vecx: %s not matched", cx->c_name());
        }
    }
    
    return match;
}


bool PolicyRule::match_addrgrp_vecx(std::vector<std::shared_ptr<AddressObject>> &sources, std::vector< baseHostCX* >& vecx) {
    bool match = false;
    
    int idx = -1;
    for(auto cx: vecx) {
        ++idx;

        match = match_addrgrp_cx(sources,cx);
        if(match) {
            _deb("PolicyRule::match_addrgrp_vecx: %s matched",cx->c_name());
            break;
        } else {
            _deb("PolicyRule::match_addrgrp_vecx: %s not matched",cx->c_name());
        }
    }
    
    return match;
}


bool PolicyRule::match(baseProxy* p) {
    
    bool lmatch = false;
    bool lpmatch = false;
    bool rmatch = false;
    bool rpmatch = false;
    
    if(p != nullptr) {

        lmatch = match_addrgrp_vecx(src,p->ls()) || match_addrgrp_vecx(src,p->lda());
        if(!lmatch) goto end;

        lpmatch = match_rangegrp_vecx(src_ports,p->ls()) || match_rangegrp_vecx(src_ports,p->lda());
        if(!lpmatch) goto end;

        rmatch = match_addrgrp_vecx(dst,p->rs()) || match_addrgrp_vecx(dst,p->rda());
        if(!rmatch) goto end;

        rpmatch = match_rangegrp_vecx(dst_ports,p->rs()) || match_rangegrp_vecx(dst_ports,p->rda());
        if(!rpmatch) goto end;

        end:

        if (lmatch && lpmatch && rmatch && rpmatch) {
            _inf("PolicyRule::match %s OK", p->to_string(iINF).c_str());
            cnt_matches++;

            return true;

        } else {
            _dia("PolicyRule::match %s FAILED: %d:%d->%d:%d", p->to_string(iINF).c_str(), lmatch, lpmatch, rmatch, rpmatch);
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

    if(!l.empty()) {
        ls = l[0]->to_string();
    }
    if(!r.empty()) {
        rs = r[0]->to_string();
    }


    lmatch = match_addrgrp_vecx(src,l);
    if(!lmatch) goto end;

    lpmatch = match_rangegrp_vecx(src_ports,l);
    if(!lpmatch) goto end;

    rmatch = match_addrgrp_vecx(dst,r);
    if(!rmatch) goto end;

    rpmatch = match_rangegrp_vecx(dst_ports,r);
    if(!rpmatch) goto end;
    
    
    if(*log.level() >= DEB ) {
        for(auto i: l) _dum("PolicyRule::match_lr L: %s", i->to_string().c_str());
        for(auto i: r) _dum("PolicyRule::match_lr R: %s", i->to_string().c_str());
        _deb("PolicyRule::match_lr Success: %d:%d->%d:%d", lmatch, lpmatch, rmatch, rpmatch);
    }

    end:
    
    
    if (lmatch && lpmatch && rmatch && rpmatch) {
        _inf("PolicyRule::match_lr %s <+> %s OK", ls.c_str(), rs.c_str());
        cnt_matches++;
        
        return true;
    } else {
        _dia("PolicyRule::match_lr %s <+> %s FAILED: %d:%d->%d:%d", ls.c_str(), rs.c_str(), lmatch, lpmatch, rmatch, rpmatch);
    }

    return false;
}


