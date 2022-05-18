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

#include <proxy/mitmhost.hpp>
#include <proxy/mitmcom.hpp>
#include <display.hpp>
#include <log/logger.hpp>
#include <cfgapi.hpp>
#include <inspect/sigfactory.hpp>
#include <inspect/sxsignature.hpp>
#include <inspect/engine/http.hpp>

bool MitmHostCX::ask_destroy() {
    error(true);
    return true;
}

std::string MitmHostCX::to_string(int verbosity) const {

    std::stringstream ret;

    if(verbosity > iINF) {
        ret << "MitmHostCX:";

        if (parent_proxy()) {
            ret << "[" << parent_flag() << "]:";
        }
    }
    ret << "<" << AppHostCX::to_string(verbosity) << ">";

    return ret.str();
}


MitmHostCX::MitmHostCX(baseCom* c, const char* h, const char* p ) : AppHostCX::AppHostCX(c,h,p) {
    _deb("MitmHostCX: constructor %s:%s", h, p);
    load_signatures();
}

MitmHostCX::MitmHostCX( baseCom* c, int s ) : AppHostCX::AppHostCX(c,s) {
    _deb("MitmHostCX: constructor %d", s);
    load_signatures();
}

std::size_t MitmHostCX::process_in() {

    // eliminate this completely
    _if_deb {
        // incoming data are in the readbuf
        auto const *ptr = baseHostCX::readbuf()->data();
        auto len = baseHostCX::readbuf()->size();

        // our only processing: hex dup the payload to the log
        _dum("Incoming data(%s):\r\n %s", this->c_type(), hex_dump(ptr, static_cast<int>(len), 4, 0, true).c_str());
    }

    if(opt_engines_enabled and engine_ctx.signature) {
        auto sig = std::dynamic_pointer_cast<MyDuplexFlowMatch>(engine_ctx.signature);

        if(sig and not sig->sig_engine.empty()) {
            engine_run(sig->sig_engine, engine_ctx);
        }
    }

    return baseHostCX::process_in();
}

std::size_t MitmHostCX::process_out() {

    if(opt_engines_enabled and engine_ctx.signature) {
        auto sig = std::dynamic_pointer_cast<MyDuplexFlowMatch>(engine_ctx.signature);

        if(sig and not sig->sig_engine.empty()) {
            engine_run(sig->sig_engine, engine_ctx);
        }
    }

    return baseHostCX::process_out();
}

void MitmHostCX::load_signatures() {

    _deb("MitmHostCX::load_signatures: start");

    make_sig_states(starttls_sensor(), SigFactory::get().tls() );
    make_sig_states(base_sensor(), SigFactory::get().base());

    auto& factory_signatures = SigFactory::get().signature_tree();

    for(auto const& [name, index ]: factory_signatures.name_index) {

        auto factory_group = factory_signatures.group(name.c_str(), false);
        if(factory_group) {

            // look if we have group too
            auto my_group = signatures().group(name.c_str(), false);

            // create group if it doesn't exist
            if(not my_group) {
                auto n_index = signatures().group_add(name.c_str(), false); // add disabled group
                // assign my_group with a new index-ed group
                my_group = signatures().sensors_[n_index];
            }

            make_sig_states(my_group, factory_group);
        }
    }
    _deb("MitmHostCX::load_signatures: stop");
}


void MitmHostCX::engine_run(std::string const& name, sx::engine::EngineCtx &e) const {

    if(name == "http1") {
        sx::engine::http::v1::start(e);
    } else if(name == "http2") {
#ifdef USE_HTTP2
        sx::engine::http::v2::start(e);
#endif
    } else {
        _deb("unknown engine_run: %s", name.c_str());
    }
}



void MitmHostCX::inspect(char side) {

    if(flow().data().size() > inspect_cur_flow_size) {
        _deb("MitmHostCX::inspect: flow size change: %d", flow().data().size());
        inspect_flow_same_bytes = 0;
    }
    
    if(flow().data().size() > inspect_cur_flow_size ||
       (flow().data().size() == inspect_cur_flow_size &&
                        flow().data().back().second->size() > inspect_flow_same_bytes) ) {

        if(flow().data().size() == inspect_cur_flow_size) {

            _deb("MitmHostCX::inspect: new data in the  same flow size %d", flow().data().size());

        }

        _deb("MitmHostCX::inspect: inspector loop:");
        for(auto const& inspector: inspectors_) {

            bool for_me = inspector->interested(this);
            bool is_completed = inspector->completed();
            if( for_me && (! is_completed )) {
                inspector->update(this);
                
                inspect_verdict = inspector->verdict();
                inspect_verdict_response = inspector->verdict_response();

                _dia("MitmHostCX::inspect[%s]: verdict %d", inspector->c_type(), inspect_verdict);
                if(inspect_verdict == Inspector::OK) {
                    //
                } else if (inspect_verdict == Inspector::CACHED) {
                    // if connection can be populated by cache, close right side.
                    
                    baseHostCX* p = nullptr;
                    side == 'l' || side == 'L' ? p = peer() : p = this;

                    // NOTE: this doesn't have to be really the best idea, though it is working well
                    //       in most cases

                    auto* verdict_target = dynamic_cast<AppHostCX*>(p);
                    if(verdict_target != nullptr) {
                        inspector->apply_verdict(verdict_target);

                        break;
                    } else {
                        _err("cannot apply verdict on generic cx");
                    }
                } 
            }
        }
        _deb("MitmHostCX::inspect: inspector loop end.");
        
        inspect_cur_flow_size = flow().data().size();
        inspect_flow_same_bytes  = flow().data().back().second->size();
    }
}


void MitmHostCX::on_detect(std::shared_ptr<duplexFlowMatch> x_sig, flowMatchState& s, vector_range& r) {

    auto sig_sig = std::dynamic_pointer_cast<MyDuplexFlowMatch>(x_sig);

    if(! sig_sig) {
        _war("signature of unknown attributes matched: %s", x_sig->name().c_str());
    }

    bool reported = false;

    // log to wildcard logger
    auto xlog = logan::get();
    if( xlog->level("inspect") >= static_cast<unsigned int>(sig_sig->sig_severity)) {
        log.log(loglevel(sig_sig->sig_severity), log.topic(), "matching signature: cat='%s', name='%s'",
                sig_sig->sig_category.c_str(),
                sig_sig->name().c_str());

        reported = true;
    }

    if(! reported) {
        // diagnose on "inspect" topic
        _dia("matching signature: cat='%s', name='%s' at %s",
             sig_sig->sig_category.c_str(),
             sig_sig->name().c_str(),
             vrangetos(r).c_str());
    }
    this->comlog().append( string_format("\nDetected application: cat='%s', name='%s'\n",
            sig_sig->sig_category.c_str(),
            sig_sig->name().c_str()));


    auto prep_ctx = [&]() {
        engine_ctx.origin = this;
        engine_ctx.flow_pos = flow().data().size() - 1;
        engine_ctx.signature = x_sig;
    };

    if(not sig_sig->sig_engine.empty()) {
        prep_ctx();
    }

    // look if signature enables other groups
    if(auto const& gn = sig_sig->sig_enables;  not gn.empty()) {

        auto gi = signatures().group_index(gn.c_str());
        if(gi.has_value()) {

            _dia("signature enabled %s signature group", gn.c_str());
            signatures().set(gi.value(), true);
        }
    }
}

void MitmHostCX::on_starttls() {

    _dia("we should now handover myself to SSL worker");

    // we know this side is client
//         delete ();
//         delete peercom();

    auto master = com()->master();

    com(new MySSLMitmCom());
    peer()->com(new MySSLMitmCom());

    peer(peer()); // this will re-init
    peer()->peer(this);

    com()->master(master);
    peer()->com()->master(master);

    _dia("peers set");

    // set flag to wait for the peer to finish spoofing

    waiting_for_peercom(true);



    SSLCom* ptr;
    ptr = dynamic_cast<SSLCom*>(peercom());
    if (ptr != nullptr) ptr->upgrade_client_socket(peer()->socket());
    ptr = dynamic_cast<SSLCom*>(com());
    if (ptr != nullptr) ptr->upgrade_server_socket(socket());

    CfgFactory::get()->policy_apply_tls(matched_policy(), com());
    CfgFactory::get()->policy_apply_tls(matched_policy(), peercom());

    comlog().append("\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");

    // mark as opening to not wait for SSL handshake (typically) 1 hour
    opening(true);

    _dia("on_starttls finished");
}


