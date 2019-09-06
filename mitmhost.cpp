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

#include <mitmhost.hpp>
#include <display.hpp>
#include <logger.hpp>
#include <cfgapi.hpp>

DEFINE_LOGGING(MitmHostCX)

std::vector<duplexFlowMatch*> sigs_starttls;
std::vector<duplexFlowMatch*> sigs_detection;

bool MitmHostCX::ask_destroy() {
    error(true);
    return true;
}

std::string MitmHostCX::to_string(int verbosity) {

    std::stringstream ret;

    if(parent_proxy()) {
        ret << "MitmHostCX[" << parent_flag() << "]:" << parent_proxy()->to_string(iINF);
    } else {
        ret << "MitmHostCX: " << AppHostCX::name();
    }

    return ret.str();
}



baseCom* MySSLMitmCom::replicate() {
    return new MySSLMitmCom();
}

bool MySSLMitmCom::spoof_cert(X509* x, SpoofOptions& spo) {
    
    //std::string cert = SSLFactory::print_cert(x);
    //log().append("\n ==== Server certificate:\n" + cert  + "\n ====\n");

    bool r = baseSSLMitmCom::spoof_cert(x,spo);

    //EXT___("MySSLMitmCom::spoof_cert: cert:\n%s",cert.c_str());

    return r;
}


MitmHostCX::MitmHostCX(baseCom* c, const char* h, const char* p ) : AppHostCX::AppHostCX(c,h,p) {
    log = logan::create("inspect");

    DEB___("MitmHostCX: constructor %s:%s",h,p);
    load_signatures();
};

MitmHostCX::MitmHostCX( baseCom* c, int s ) : AppHostCX::AppHostCX(c,s) {
    log = logan::create("inspect");

    DEB___("MitmHostCX: constructor %d",s);
    load_signatures();
};

int MitmHostCX::process() {

    // incoming data are in the readbuf
    unsigned char *ptr = baseHostCX::readbuf()->data();
    unsigned int len = baseHostCX::readbuf()->size();

    // our only processing: hex dup the payload to the log
    DUMS___("Incoming data(" + this->name() + "):\n" +hex_dump(ptr,len));

    //  read buffer will be truncated by 'len' bytes. Note: truncated bytes are LOST.
    return len;
};

void MitmHostCX::load_signatures() {

    DEBS___("MitmHostCX::load_signatures: start");

    zip_signatures(starttls_sensor(),sigs_starttls);
    zip_signatures(sensor(),sigs_detection);

    DEBS___("MitmHostCX::load_signatures: stop");
};

void MitmHostCX::on_detect_www_get(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r) {
    if(! r.empty()) {
        std::pair<char,buffer*>& get = flow().flow()[0];
        std::pair<char,buffer*>& status = flow().flow()[0];

        buffer* buffer_get = get.second;

        std::string buffer_data_string((const char*)buffer_get->data(),0,buffer_get->size());

        //INFS___(std::string((const char*)buffer_get->data(),0,buffer_get->size()));
        std::regex re_get("(GET|POST) *([^ \r\n\?]+)([^ \r\n]*)");
        std::smatch m_get;

        std::regex re_ref("Referer: *([^ \r\n]+)");
        std::smatch m_ref;

        std::regex re_host("Host: *([^ \r\n]+)");
        std::smatch m_host;


        std::string str_temp;
        std::string print_request;


        if(std::regex_search (buffer_data_string, m_ref, re_ref)) {

            str_temp = m_ref[1].str();

            //don't add referer to log.
            //print_request += str_temp;

            if(application_data == nullptr) {
                application_data = new app_HttpRequest;
            }

            auto* app_request = dynamic_cast<app_HttpRequest*>(application_data);
            if(app_request != nullptr) {
                app_request->referer = str_temp;
                DEB___("Referer: %s",ESC(app_request->referer));
            }


        }

        if(std::regex_search (buffer_data_string, m_host, re_host))  {
            if(! m_host.empty()) {
                str_temp = m_host[1].str();
                print_request += str_temp;

                if(application_data == nullptr) {
                    application_data = new app_HttpRequest;
                }

                auto* app_request = dynamic_cast<app_HttpRequest*>(application_data);
                if(app_request != nullptr) {
                    app_request->host = str_temp;
                    DIA___("Host: %s",app_request->host.c_str());


                    // FIXME: should be some config variable
                    bool check_inspect_dns_cache = true;
                    if(check_inspect_dns_cache) {

                        std::scoped_lock<std::recursive_mutex> d_(DNS::get().dns_lock());

                        DNS_Response* dns_resp_a = DNS::get().dns_cache().get("A:" + app_request->host);
                        DNS_Response* dns_resp_aaaa = DNS::get().dns_cache().get("AAAA:" + app_request->host);

                        if(dns_resp_a && com()->l3_proto() == AF_INET) {
                            DEB___("HTTP inspection: Host header matches DNS: %s",ESC(dns_resp_a->question_str_0()));
                        } else if(dns_resp_aaaa && com()->l3_proto() == AF_INET6) {
                            DEB___("HTTP inspection: Host header matches IPv6 DNS: %s",ESC(dns_resp_aaaa->question_str_0()));
                        }
                        else {
                            WAR___("HTTP inspection: 'Host' header value '%s' DOESN'T match DNS!", app_request->host.c_str());
                        }
                    }
                }
            }
        }

        if(std::regex_search (buffer_data_string, m_get, re_get)) {
            if(m_get.size() > 1) {
                str_temp = m_get[2].str();
                print_request += str_temp;

                if(application_data == nullptr) {
                    application_data = new app_HttpRequest;
                }

                auto* app_request = dynamic_cast<app_HttpRequest*>(application_data);
                if(app_request != nullptr) {
                    app_request->uri = str_temp;
                    DIA___("URI: %s",ESC(app_request->uri));
                }

                if(app_request && m_get.size() > 2) {
                    str_temp = m_get[3].str();
                    app_request->params = str_temp;
                    DIA___("params: %s",ESC(app_request->params));

                    //print_request += str_temp;
                }
            }
        }


        auto* app_request = dynamic_cast<app_HttpRequest*>(application_data);
        if(app_request != nullptr) {
            // detect protocol (plain vs ssl)
            auto* proto_com = dynamic_cast<SSLCom*>(com());
            if(proto_com != nullptr) {
                app_request->proto="https://";
                app_request->is_ssl = true;
            } else {
                app_request->proto="http://" ;
            }


            INF___("http request: %s",ESC(app_request->hr()));
        } else {
            INF___("http request: %s (app_request cast failed)",ESC(print_request));
        }


        // this is the right way, but not here
        // replacement(REPLACE_REDIRECT);
        // replacement(REPLACE_BLOCK);

        // we have to specify that we are replaceable!
        replacement_type_ = REPLACETYPE_HTTP;
    }
}


void MitmHostCX::inspect(char side) {


    if(inspect_verdict == Inspector::CACHED)
        return;

    AppHostCX::inspect(side);
    
    if(flow().flow().size() > inspect_cur_flow_size) {
        log.deb("MitmHostCX::inspect: flow size change: %d",flow().flow().size());
        inspect_flow_same_bytes = 0;
    }
    
    if(flow().flow().size() > inspect_cur_flow_size || 
                (flow().flow().size() == inspect_cur_flow_size && flow().flow().back().second->size() > inspect_flow_same_bytes) ) {

        if(flow().flow().size() == inspect_cur_flow_size) {

            log.deb("MitmHostCX::inspect: new data in the  same flow size %d", flow().flow().size());

        }
        
        log.deb("MitmHostCX::inspect: inspector loop:");
        for(Inspector* inspector: inspectors_) {
            if(inspector->interested(this) && (! inspector->completed() )) {
                inspector->update(this);
                
                inspect_verdict = inspector->verdict();
                
                log.dia("MitmHostCX::inspect[%s]: verdict %d",inspector->c_name(), inspect_verdict);
                if(inspect_verdict == Inspector::OK) {
                    //
                } else if (inspect_verdict == Inspector::CACHED) {
                    // if connection can be populated by cache, close right side.
                    
                    baseHostCX* p = nullptr;
                    side == 'l' || side == 'L' ? p = peer() : p = this;
                    p->error(true);
                    
                    auto* verdict_target = dynamic_cast<AppHostCX*>(p);
                    if(verdict_target != nullptr) {
                        inspector->apply_verdict(verdict_target);
                        break;
                    } else {
                        log.err("cannot apply verdict on generic cx");
                    }
                } 
            }
        }
        log.deb("MitmHostCX::inspect: inspector loop end.");
        
        inspect_cur_flow_size = flow().flow().size();
        inspect_flow_same_bytes  = flow().flow().back().second->size();
    }
}


void MitmHostCX::on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r) {

    auto* sig_sig = dynamic_cast<MyDuplexFlowMatch*>(x_sig);


    if(sig_sig) {

        // log to wildcard logger
        logan::log(loglevel(sig_sig->severity),"matching signature: cat='%s', name='%s'",
                sig_sig->category.c_str(),
                sig_sig->name().c_str());

        // diagnose on "inspect" topic
        log.dia("matching signature: cat='%s', name='%s' at %s",
                sig_sig->category.c_str(),
                sig_sig->name().c_str(),
                vrangetos(r).c_str());

        this->comlog().append( string_format("\nDetected application: cat='%s', name='%s'\n",
                sig_sig->category.c_str(),
                sig_sig->name().c_str()));


        if(sig_sig->category ==  "www" && sig_sig->name() == "http/get|post") {
            on_detect_www_get(x_sig,s,r);
        }
    } else {
        WAR___("signature of unknown attributes matched: ", x_sig->name());
    }
}

void MitmHostCX::on_starttls() {

    DIAS___("we should now handover myself to SSL worker");

    // we know this side is client
//         delete ();
//         delete peercom();

    com_ = new MySSLMitmCom();
    baseCom* pcom = new MySSLMitmCom();

    //com()->init(this);

    peer()->com(pcom);
    peer(peer()); // this will re-init
    peer()->peer(this);

    DIAS___("peers set");

    // set flag to wait for the peer to finish spoofing

    waiting_for_peercom(true);



    SSLCom* ptr;
    ptr = dynamic_cast<SSLCom*>(peercom());
    if (ptr != nullptr) ptr->upgrade_client_socket(peer()->socket());
    ptr = dynamic_cast<SSLCom*>(com());
    if (ptr != nullptr) ptr->upgrade_server_socket(socket());

    CfgFactory::get().policy_apply_tls(matched_policy(), com());
    CfgFactory::get().policy_apply_tls(matched_policy(), peercom());

    comlog().append("\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");

    // mark as opening to not wait for SSL handshake (typically) 1 hour
    opening(true);
    
    DIAS___("on_starttls finished");
}


