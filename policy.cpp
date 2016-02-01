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

#include <policy.hpp>


bool PolicyRule::match_addrgrp_cx(std::vector< AddressObject* >& sources, baseHostCX* cx) {
    bool match = false;
    
    if(sources.size() == 0) {
        match = true;
//                 DIAS_("PolicyRule: matched ");
    } else {
        CIDR* l = cidr_from_str(cx->host().c_str());
        for(std::vector<AddressObject*>::iterator j = sources.begin(); j != sources.end(); ++j ) {
            AddressObject* comp = (*j);
            
            if(comp->match(l)) {
                if(LEV_(DIA)) {
                    char* a = cidr_to_str(l);
                    DIA_("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: matched",a,comp->to_string().c_str());
                    delete a;
                }
                match = true;
                break;
            } else {
                if(LEV_(DIA)) {
                    char* a = cidr_to_str(l);
                    DIA_("PolicyRule::match_addrgrp_cx: comparing %s with rule %s: not matched",a,comp->to_string().c_str());
                    delete[] a;
                }
            }
        }
        cidr_free(l);
    }

    return match;
}

bool PolicyRule::match_rangegrp_cx(std::vector< range >& ranges, baseHostCX* cx) {
    bool match = false;
    
    if(ranges.size() == 0) {
        match = true;
//                 DIAS_("PolicyRule: matched ");
    } else {
        int p = std::stoi(cx->port());
        for(std::vector<range>::iterator j = ranges.begin(); j != ranges.end(); ++j ) {
            range& comp = (*j);
            if((p >= comp.first) && (p <= comp.second)) {
                DIA_("PolicyRule::match_rangergrp_cx: comparing %d with %s: matched",p,rangetos(comp).c_str());
                match = true;
                break;
            } else {
                DIA_("PolicyRule::match_rangergrp_cx: comapring %d with %s: not matched",p,rangetos(comp).c_str());
            }
        }
    }

    return match;
}

bool PolicyRule::match_rangegrp_vecx(std::vector< range >& ranges, std::vector< baseHostCX* >& vecx) {
    bool match = false;
    
    int idx = -1;
    for(std::vector<baseHostCX*>::iterator i = vecx.begin(); i != vecx.end(); ++i ) {
        ++idx;
        baseHostCX* cx = (*i);
        
        match = match_rangegrp_cx(ranges,cx);
        if(match) {
            DIA_("PolicyRule::match_rangegrp_vecx: %s matched",cx->c_name());
            break;
        } else {
            DIA_("PolicyRule::match_rangegrp_vecx: %s not matched",cx->c_name())
        }
    }
    
    return match;
}


bool PolicyRule::match_addrgrp_vecx(std::vector< AddressObject* >& sources, std::vector< baseHostCX* >& vecx) {
    bool match = false;
    
    int idx = -1;
    for(std::vector<baseHostCX*>::iterator i = vecx.begin(); i != vecx.end(); ++i ) {
        ++idx;
        baseHostCX* cx = (*i);
        
        match = match_addrgrp_cx(sources,cx);
        if(match) {
            DIA_("PolicyRule::match_addrgrp_vecx: %s matched",cx->c_name())
            break;
        } else {
            DIA_("PolicyRule::match_addrgrp_vecx: %s not matched",cx->c_name())
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
        DIAS_("PolicyRule::match");
        
        lmatch = match_addrgrp_vecx(src,p->ls()) || match_addrgrp_vecx(src,p->lda());
        if(!lmatch) goto end;

        lpmatch = match_rangegrp_vecx(src_ports,p->ls()) || match_rangegrp_vecx(src_ports,p->lda());
        if(!lpmatch) goto end;

        rmatch = match_addrgrp_vecx(dst,p->rs()) || match_addrgrp_vecx(dst,p->rda());
        if(!rmatch) goto end;

        rpmatch = match_rangegrp_vecx(dst_ports,p->rs()) || match_rangegrp_vecx(dst_ports,p->rda());
        if(!rpmatch) goto end;
        
    } else {
        DIAS_("PolicyRule::match: p is nullptr");
    }
    
    end:
    
    if (lmatch && lmatch && rmatch && rpmatch) {
        DIAS_("PolicyRule::match ok");
        return true;
    } else {
        DIA_("PolicyRule::match failed: %d:%d->%d:%d",lmatch,lpmatch,rmatch,rpmatch);
    }

    return false;
}

bool PolicyRule::match(std::vector<baseHostCX*>& l, std::vector<baseHostCX*>& r) {
    bool lmatch = false;
    bool lpmatch = false;
    bool rmatch = false;
    bool rpmatch = false;
    

    DIAS_("PolicyRule::match_lr");
    
    lmatch = match_addrgrp_vecx(src,l);
    if(!lmatch) goto end;

    lpmatch = match_rangegrp_vecx(src_ports,l);
    if(!lpmatch) goto end;

    rmatch = match_addrgrp_vecx(dst,r);
    if(!rmatch) goto end;

    rpmatch = match_rangegrp_vecx(src_ports,r);
    if(!rpmatch) goto end;
    
    end:
    
    if (lmatch && lmatch && rmatch && rpmatch) {
        DIAS_("PolicyRule::match_lr ok");
        return true;
    } else {
        DIA_("PolicyRule::match_lr failed: %d:%d->%d:%d",lmatch,lpmatch,rmatch,rpmatch);
    }

    return false;
}

PolicyRule::~PolicyRule() {
}

