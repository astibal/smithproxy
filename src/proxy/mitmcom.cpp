#include <proxy/mitmcom.hpp>

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
