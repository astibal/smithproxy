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
#include <display.hpp>
#include <log/logger.hpp>
#include <cfgapi.hpp>
#include <inspect/sigfactory.hpp>

bool MitmHostCX::ask_destroy() {
    error(true);
    return true;
}

std::string MitmHostCX::to_string(int verbosity) const {

    std::stringstream ret;

    ret << "MitmHostCX:";

    if(parent_proxy()) {
        ret << "[" << parent_flag() << "]:";
    }

    ret << "<" << AppHostCX::to_string(verbosity) << ">";

    return ret.str();
}



baseCom* MySSLMitmCom::replicate() {
    return new MySSLMitmCom();
}

bool MySSLMitmCom::spoof_cert(X509* x, SpoofOptions& spo) {
    
    //std::string cert = SSLFactory::print_cert(x);
    //comlog().append("\n ==== Server certificate:\n" + cert  + "\n ====\n");

    bool r = baseSSLMitmCom::spoof_cert(x,spo);

    //_ext("MySSLMitmCom::spoof_cert: cert:\n%s",cert.c_str());

    return r;
}


MitmHostCX::MitmHostCX(baseCom* c, const char* h, const char* p ) : AppHostCX::AppHostCX(c,h,p) {
    log = logan::attach<MitmHostCX>(this, "inspect");

    _deb("MitmHostCX: constructor %s:%s", h, p);
    load_signatures();
}

MitmHostCX::MitmHostCX( baseCom* c, int s ) : AppHostCX::AppHostCX(c,s) {
    log = logan::attach<MitmHostCX>(this, "inspect");

    _deb("MitmHostCX: constructor %d", s);
    load_signatures();
}

int MitmHostCX::process() {

    // incoming data are in the readbuf
    unsigned char *ptr = baseHostCX::readbuf()->data();
    unsigned int len = baseHostCX::readbuf()->size();

    // our only processing: hex dup the payload to the log
    _dum("Incoming data(%s):\n %s", this->c_type(), hex_dump(ptr, static_cast<int>(len)).c_str());



    //  read buffer will be truncated by 'len' bytes. Note: truncated bytes are LOST.
    return static_cast<int>(len);
}

void MitmHostCX::load_signatures() {

    _deb("MitmHostCX::load_signatures: start");

    make_sig_states(starttls_sensor(), SigFactory::get().tls() );
    make_sig_states(base_sensor(), SigFactory::get().base());

    auto& factory_signatures = SigFactory::get().signature_tree();

    for(auto const& [name, index]: factory_signatures.name_index) {

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


void MitmHostCX::engine(std::string const& name, EngineCtx e) {
    // mux to other engines from hash name->engine, now just pass to http1
    if(name == "http1") {
        engine_http1_start(e.signature, e.match_state, e.match_range);
    } else {
        _err("unknown engine: %s", name.c_str());
    }
}

void MitmHostCX::engine_http1_start_find_referrer(std::string const& data) {

    std::smatch m_ref;

    auto ix_ref = data.find("Referer: ");
    if(ix_ref != std::string::npos) {
        auto ref_start = data.substr(ix_ref, std::min(std::size_t (128), data.size() - ix_ref));
        if (std::regex_search(ref_start, m_ref, ProtoRex::http_req_ref())) {
            std::string str_temp;

            str_temp = m_ref[1].str();

            if(not application_data) {
                application_data = std::make_unique<app_HttpRequest>();
            }

            auto *app_request = dynamic_cast<app_HttpRequest *>(application_data.get());
            if (app_request != nullptr) {
                app_request->referer = str_temp;
                _deb("Referer: %s", ESC(app_request->referer));
            }
        }
    }
}

void MitmHostCX::engine_http1_start_find_host(std::string const& data) {
    auto ix_host = data.find("Host: ");
    if(ix_host != std::string::npos) {

        auto host_start = data.substr(ix_host, std::min(std::size_t (128), data.size() - ix_host));
        std::smatch m_host;

        if (std::regex_search(host_start, m_host, ProtoRex::http_req_host())) {
            if (!m_host.empty()) {
                auto str_temp = m_host[1].str();

                if (not application_data) {
                    application_data = std::make_unique<app_HttpRequest>();
                }

                auto *app_request = dynamic_cast<app_HttpRequest *>(application_data.get());
                if (app_request != nullptr) {
                    app_request->host = str_temp;
                    _dia("Host: %s", app_request->host.c_str());


                    // NOTE: should be some config variable
                    bool check_inspect_dns_cache = true;
                    if (check_inspect_dns_cache) {

                        std::scoped_lock<std::recursive_mutex> d_(DNS::get().dns_lock());

                        auto dns_resp_a = DNS::get().dns_cache().get("A:" + app_request->host);
                        auto dns_resp_aaaa = DNS::get().dns_cache().get("AAAA:" + app_request->host);

                        if (dns_resp_a && com()->l3_proto() == AF_INET) {
                            _deb("HTTP inspection: Host header matches DNS: %s", ESC(dns_resp_a->question_str_0()));
                        } else if (dns_resp_aaaa && com()->l3_proto() == AF_INET6) {
                            _deb("HTTP inspection: Host header matches IPv6 DNS: %s",
                                 ESC(dns_resp_aaaa->question_str_0()));
                        } else {
                            _war("HTTP inspection: 'Host' header value '%s' DOESN'T match DNS!",
                                 app_request->host.c_str());
                        }
                    }
                }
            }
        }
    }
}

void MitmHostCX::engine_http1_start_find_method(std::string const& data) {
    auto method_start = data.substr(0, std::min(std::size_t(128), data.size()));
    std::smatch m_get;

    if(std::regex_search (method_start, m_get, ProtoRex::http_req_get() )) {
        if(m_get.size() > 1) {

            auto str_temp = m_get[2].str();

            if(not application_data) {
                application_data = std::make_unique<app_HttpRequest>();
            }

            auto* app_request = dynamic_cast<app_HttpRequest*>(application_data.get());
            if(app_request != nullptr) {
                app_request->uri = str_temp;
                _dia("URI: %s", ESC(app_request->uri));
            }

            if(app_request && m_get.size() > 2) {
                str_temp = m_get[3].str();
                app_request->params = str_temp;
                _dia("params: %s", ESC(app_request->params));

            }
        }
    }
}


void MitmHostCX::engine_http1_start(const std::shared_ptr<duplexFlowMatch> &x_sig, flowMatchState& s, vector_range& r) {

    if(r.empty()) return;

    std::pair<char,buffer*>& http_request1 = flow().flow()[0];

    buffer* http_request1_buffer = http_request1.second;

    // limit this rather info/convenience regexing to 128 bytes

    // Actually for unknown reason, sample size 512 (and more) was crashing deep in std::regex on alpine platform.
    // Suspicion is it has to do something with MUSL or alpine platform specific. 256 is good enough to set for general use,
    // as there is nothing dependant on full URI and more can slow box down for not real benefit.


    std::string buffer_data_string((const char*)http_request1_buffer->data(), http_request1_buffer->size());


    engine_http1_start_find_method(buffer_data_string);
    engine_http1_start_find_host(buffer_data_string);
    engine_http1_start_find_referrer(buffer_data_string);


    auto engine_http1_set_proto = [this]() {
        auto* app_request = dynamic_cast<app_HttpRequest*>(application_data.get());
        if(app_request != nullptr) {
            // detect protocol (plain vs ssl)
            auto* proto_com = dynamic_cast<SSLCom*>(com());
            if(proto_com != nullptr) {
                app_request->proto="https://";
                app_request->is_ssl = true;
            } else {
                app_request->proto="http://" ;
            }


            _inf("http request: %s",ESC(app_request->str()));
        } else {
            _err("http request: app_request failed");
        }
    };


    engine_http1_set_proto();

    replacement_type_ = REPLACETYPE_HTTP;
}


void MitmHostCX::inspect(char side) {

    if(flow().flow().size() > inspect_cur_flow_size) {
        _deb("MitmHostCX::inspect: flow size change: %d", flow().flow().size());
        inspect_flow_same_bytes = 0;
    }
    
    if(flow().flow().size() > inspect_cur_flow_size || 
                (flow().flow().size() == inspect_cur_flow_size && flow().flow().back().second->size() > inspect_flow_same_bytes) ) {

        if(flow().flow().size() == inspect_cur_flow_size) {

            _deb("MitmHostCX::inspect: new data in the  same flow size %d", flow().flow().size());

        }

        _deb("MitmHostCX::inspect: inspector loop:");
        for(auto const& inspector: inspectors_) {

            bool for_me = inspector->interested(this);
            bool is_completed = inspector->completed();
            if( for_me && (! is_completed )) {
                inspector->update(this);
                
                inspect_verdict = inspector->verdict();

                _dia("MitmHostCX::inspect[%s]: verdict %d", inspector->c_type(), inspect_verdict);
                if(inspect_verdict == Inspector::OK) {
                    //
                } else if (inspect_verdict == Inspector::CACHED) {
                    // if connection can be populated by cache, close right side.
                    
                    baseHostCX* p = nullptr;
                    side == 'l' || side == 'L' ? p = peer() : p = this;

                    // NOTE: this doesn't have to be really best idea, though it is working well
                    //       in most cases
                    //                    p->error(true);

                    auto* verdict_target = dynamic_cast<AppHostCX*>(p);
                    if(verdict_target != nullptr) {
                        inspector->apply_verdict(verdict_target);

                        // reset it back to ok for further queries
                        // inspector->verdict(Inspector::OK);
                        break;
                    } else {
                        _err("cannot apply verdict on generic cx");
                    }
                } 
            }
        }
        _deb("MitmHostCX::inspect: inspector loop end.");
        
        inspect_cur_flow_size = flow().flow().size();
        inspect_flow_same_bytes  = flow().flow().back().second->size();
    }
}


void MitmHostCX::on_detect(std::shared_ptr<duplexFlowMatch> x_sig, flowMatchState& s, vector_range& r) {

    auto sig_sig = std::dynamic_pointer_cast<MyDuplexFlowMatch>(x_sig);

    if(! sig_sig) {
        _war("signature of unknown attributes matched: %s", x_sig->name().c_str());
    }

    bool reported = false;

    // log to wildcard logger
    if( logan::get()["inspect"]->level() >= static_cast<unsigned int>(sig_sig->sig_severity)) {
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


    // make this code deprecated and call it only if engine is not present in the configuration
    if(sig_sig->sig_category == "www" && sig_sig->name() == "http/get|post") {
        if(sig_sig->sig_engine.empty()) {
            engine_http1_start(x_sig, s, r);
        }
    }

    if(not sig_sig->sig_engine.empty()) {
        auto cx = EngineCtx::create(this, x_sig, s, r);
        engine(sig_sig->sig_engine, cx);
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


