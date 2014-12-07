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

#include <mitmhost.hpp>
#include <display.hpp>
#include <logger.hpp>

std::vector<duplexFlowMatch*> sigs_starttls;
std::vector<duplexFlowMatch*> sigs_detection;

baseCom* MySSLMitmCom::replicate() { 
    return new SSLMitmCom(); 
}

bool MySSLMitmCom::spoof_cert(X509* x) {
    std::string cert = SSLCertStore::print_cert(x);
    log().append("\n ==== Server certificate:\n" + cert  + "\n ====\n");
    bool r = SSLMitmCom::spoof_cert(x);
    
    EXT_("MySSLMitmCom::spoof_cert: cert:\n%s",cert.c_str());
    
    return r;
}


MitmHostCX::MitmHostCX(baseCom* c, const char* h, const char* p ) : AppHostCX::AppHostCX(c,h,p) {
    DEB_("MitmHostCX: constructor %s:%s",h,p);
    load_signatures();
};

MitmHostCX::MitmHostCX( baseCom* c, int s ) : AppHostCX::AppHostCX(c,s) {
    DEB_("MitmHostCX: constructor %d",s);
    load_signatures();
};

int MitmHostCX::process() {

    // incoming data are in the readbuf
    unsigned char *ptr = baseHostCX::readbuf()->data();
    unsigned int len = baseHostCX::readbuf()->size();
    
    // our only processing: hex dup the payload to the log
    DUMS_("Incoming data(" + this->name() + "):\n" +hex_dump(ptr,len));
    
    //  read buffer will be truncated by 'len' bytes. Note: truncated bytes are LOST.
    return len;
};

void MitmHostCX::load_signatures() {
    
    DEBS_("MitmHostCX::load_signatures: start");
    
    zip_signatures(starttls_sensor(),sigs_starttls);
    zip_signatures(sensor(),sigs_detection);
    
    DEBS_("MitmHostCX::load_signatures: stop");
};

void MitmHostCX::on_detect(duplexFlowMatch* x_sig, flowMatchState& s, vector_range& r) {
    
    MyDuplexFlowMatch* sig_sig = (MyDuplexFlowMatch*)x_sig;

    WAR_("Connection from %s matching signature: cat='%s', name='%s'",this->full_name('L').c_str(), sig_sig->category.c_str(), sig_sig->name().c_str());
    DEB_("Connection from %s matching signature: cat='%s', name='%s' at %s",this->full_name('L').c_str(), sig_sig->category.c_str(), sig_sig->name().c_str(), vrangetos(r).c_str());
    
    this->log().append( string_format("\nDetected application: cat='%s', name='%s'\n",sig_sig->category.c_str(), sig_sig->name().c_str()));
}

void MitmHostCX::on_starttls() {

    DIAS_("we should now handover myself to SSL worker");
    
    // we know this side is client
//         delete ();
//         delete peercom();

    com_ = new MySSLMitmCom();
    com()->init(this);
    
    peer()->com(new SSLMitmCom());
    peer(peer()); // this will re-init
    peer()->peer(this);
    
    DIAS_("peers set");
    
    // set flag to wait for the peer to finish spoofing

    paused(true);
    ((SSLCom*)peercom())->upgrade_client_socket(peer()->socket());
    ((SSLCom*)com())->upgrade_server_socket(socket());        
    
    log().append("\n STARTTLS: plain connection upgraded to SSL/TLS, continuing with inspection.\n\n");
    
    DIAS_("on_starttls finished");   
}


