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

#include <ext/lmhpp/include/lmhttpd.hpp>
#include <ext/json/json.hpp>

#include <openssl/x509.h>

static nlohmann::json json_cert(X509* x, int verbosity) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    nlohmann::json toret;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp,SSLCERTSTORE_BUFSIZE-1);
    toret["cn"] = std::string(tmp);

    X509_NAME_oneline(X509_get_subject_name(x), tmp, SSLCERTSTORE_BUFSIZE-1);
    toret["subject"] = std::string(tmp);


    X509_NAME* issuer = X509_get_issuer_name(x);
    if(!issuer) {
        toret["issuer"] = "";
    } else {
        X509_NAME_oneline(issuer,tmp,SSLCERTSTORE_BUFSIZE-1);
        toret["issuer"] = std::string(tmp);
    }

#ifdef USE_OPENSSL11
    int pkey_nid = X509_get_signature_type(x);
#else
    int pkey_nid = OBJ_obj2nid(x->cert_info->key->algor->algorithm);
#endif

    if(verbosity > iINF) {
        const char* sslbuf = OBJ_nid2ln(pkey_nid);
        toret["sigalg"] = std::string(sslbuf);
    }

    ASN1_TIME *not_before = X509_get_notBefore(x);
    ASN1_TIME *not_after = X509_get_notAfter(x);

    SSLFactory::convert_ASN1TIME(not_before, tmp, SSLCERTSTORE_BUFSIZE-1);
    toret["valid_from"] = std::string(tmp);

    SSLFactory::convert_ASN1TIME(not_after, tmp, SSLCERTSTORE_BUFSIZE-1);
    toret["valid_to"] = std::string(tmp);


#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if (!ext_bio) {
        return toret;
    }

    if(verbosity > iINF) {
        X509V3_extensions_print(ext_bio, nullptr, exts, 0, 0);

        BUF_MEM *bptr = nullptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_CLOSE);

        std::string it(bptr->data, bptr->length);
        toret["extensions"] = it;

        BIO_free(ext_bio);
    }
#endif

    return toret;
}


static nlohmann::json json_ssl_cache_stats(struct MHD_Connection * connection) {
    SSLFactory* store = SSLCom::factory();

    int n_cache = 0;
    int n_maxsize = 0;
    {
        std::lock_guard<std::recursive_mutex> l(store->lock());
        n_cache = store->cache().cache().size();
        n_maxsize = store->cache().max_size();
    }

    nlohmann::json ret = { { "cache_size", n_cache }, { "max_size",  n_maxsize } };
    return ret;
}

static nlohmann::json json_ssl_cache_print(struct MHD_Connection * connection) {

    const char* verbosity_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "verbosity");

    SSLFactory *store = SSLCom::factory();
    bool print_refs = false;

    int verbosity = 6;
    if (verbosity_str) {
        verbosity = safe_val(verbosity_str);
        if (verbosity >= 7) {
            print_refs = true;
        }
    }

    nlohmann::json toret;

    {
        std::lock_guard<std::recursive_mutex> l_(store->lock());

        for (auto const& x: store->cache().cache()) {
            std::string fqdn = x.first;
            SSLFactory::X509_PAIR const* ptr = x.second->ptr()->keypair();

            nlohmann::json detail;

            auto name_vec = string_split(fqdn, '+');
            detail["subject"] = name_vec[0];
            detail["names"] = name_vec;

            if(print_refs) {
                int counter = x.second->count();
                int age = x.second->age();

                detail["usage"] = {
                        "accessed",  counter,
                        "age", age
                    };
            }

            detail[fqdn] =  json_cert(ptr->second, verbosity);
            toret.push_back(detail);
        }
    }

    return toret;
}


