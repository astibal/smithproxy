#include <proxy/mitmcom.hpp>
#include <proxy/mitmproxy.hpp>

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

std::string MySSLMitmCom::ssl_error_details() {
    auto ret = SSLCom::ssl_error_details();

    std::stringstream info;
    info << "Workarounds: \r\n";
    info << "  # diag ssl whitelist insert_fingerprint " << SSLFactory::fingerprint(sslcom_target_cert) << " 600\r\n";
    if(owner_cx() and owner_cx()->peer()) {
        auto l4 = whitelist_make_key_l4(owner_cx()->peer());
        info << "  # diag ssl whitelist insert_l4 " << l4 << " 600\r\n";
    }

    info << "\r\n" << ret;

    return  info.str();
};