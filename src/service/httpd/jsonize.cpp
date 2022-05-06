#include <service/httpd/jsonize.hpp>

namespace jsonize {

    nlohmann::json from(X509 *x, int verbosity) {
        char tmp[SSLCERTSTORE_BUFSIZE];
        nlohmann::json toret;

        // get info from the peer certificate
        X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, tmp, SSLCERTSTORE_BUFSIZE - 1);
        toret["cn"] = std::string(tmp);

        X509_NAME_oneline(X509_get_subject_name(x), tmp, SSLCERTSTORE_BUFSIZE - 1);
        toret["subject"] = std::string(tmp);


        X509_NAME *issuer = X509_get_issuer_name(x);
        if (!issuer) {
            toret["issuer"] = "";
        } else {
            X509_NAME_oneline(issuer, tmp, SSLCERTSTORE_BUFSIZE - 1);
            toret["issuer"] = std::string(tmp);
        }

#ifdef USE_OPENSSL11
        int pkey_nid = X509_get_signature_type(x);
#else
        int pkey_nid = OBJ_obj2nid(x->cert_info->key->algor->algorithm);
#endif

        if (verbosity > iINF) {
            const char *sslbuf = OBJ_nid2ln(pkey_nid);
            toret["sigalg"] = std::string(sslbuf);
        }

        ASN1_TIME *not_before = X509_get_notBefore(x);
        ASN1_TIME *not_after = X509_get_notAfter(x);

        SSLFactory::convert_ASN1TIME(not_before, tmp, SSLCERTSTORE_BUFSIZE - 1);
        toret["valid_from"] = std::string(tmp);

        SSLFactory::convert_ASN1TIME(not_after, tmp, SSLCERTSTORE_BUFSIZE - 1);
        toret["valid_to"] = std::string(tmp);


#ifdef USE_OPENSSL11
        const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!ext_bio) {
            return toret;
        }

        if (verbosity > iINF) {
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


    nlohmann::json from(baseCom *xcom, int verbosity) {

        nlohmann::json ret;

        auto *com = dynamic_cast<SSLCom *>(xcom);
        if (com and !com->opt_bypass) {
            auto ssl = com->get_SSL();
            SSL_SESSION* session = ssl != nullptr ? SSL_get_session(ssl) : nullptr;

            if (ssl and session) {
                auto *cipher_str = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(session));
                int has_ticket = SSL_SESSION_has_ticket(session);
                unsigned long lifetime_hint = -1;
                if (has_ticket > 0) {
                    lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
                }

                auto tls_ver = SSL_get_version(ssl);

                ret["version"] = tls_ver;
                ret["cipher"] = cipher_str;
                ret["has_ticket"] = has_ticket > 0;
                if (has_ticket) {
                    ret["ticket"]["lifetime_hint"] = lifetime_hint;
                }

                if (!com->is_server()) {
                    std::vector<std::string> ext_flags;
                    if (!com->verify_extended_info().empty()) {
                        for (auto const &ei: com->verify_extended_info()) {
                            ext_flags.emplace_back(MitmProxy::verify_flag_string_extended(ei));
                        }
                    }

                    ret["verify"] = {
                            {"origin",        SSLCom::verify_origin_str(com->verify_origin())},
                            {"sx_flag",       MitmProxy::verify_flag_string(com->verify_get())},
                            {"extended_info", ext_flags}
                    };

                }

                const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                if (sni) {
                    ret["sni"] = sni;
                }

                if (not com->alpn().empty()) {
                    ret["alpn"] = com->alpn();
                }

                auto scts = SSL_get0_peer_scts(ssl);
                int scts_len = sk_SCT_num(scts);

                if (scts_len > 0 and verbosity >= iDIA) {
                    nlohmann::json sct_entries;
                    const CTLOG_STORE *log_store = SSL_CTX_get0_ctlog_store(
                            SSLFactory::factory().default_tls_client_cx());

                    for (int i = 0; i < scts_len; i++) {
                        nlohmann::json sct_detail;

                        auto sct = sk_SCT_value(scts, i);

                        unsigned char *sct_logid{};
                        size_t sct_logid_len = 0;
                        sct_logid_len = SCT_get0_log_id(sct, &sct_logid);
                        if (sct_logid_len > 0)
                            sct_detail["sctlog_id"] = hex_print(sct_logid, sct_logid_len);

                        auto val_stat = SCT_get_validation_status(sct);
                        sct_detail["sctlog_status"] = socle::com::ssl::SCT_validation_status_str(val_stat);

                        if (verbosity >= iDEB) {
                            BioMemory bm;
                            SCT_print(sct, bm, 4, log_store);
                            sct_detail["sctlog_txt"] = bm.str();
                        }

                        sct_entries.push_back(sct_detail);
                    }

                    ret["sct"] = sct_entries;
                }
            }
        }

        return ret;
    }


    nlohmann::json from(MitmProxy* what, int verbosity) {
        nlohmann::json ret;

        std::vector<nlohmann::json> left;
        std::vector<nlohmann::json> right;


        auto host_to_json = [verbosity](baseHostCX* cx) -> nlohmann::json {
            nlohmann::json ret;
            if(auto* mh = dynamic_cast<MitmHostCX*>(cx); mh != nullptr) {
                ret = jsonize::from(mh, verbosity);
            }
            return ret;
        };

        {
            for (auto ii: what->lbs()) left.emplace_back( host_to_json(ii));
            for (auto ii: what->ls()) left.emplace_back( host_to_json(ii));
            for (auto ii: what->lda()) left.emplace_back( host_to_json(ii));
            for (auto ii: what->lpc()) left.emplace_back( host_to_json(ii));

            for (auto ii: what->rbs()) right.emplace_back( host_to_json(ii));
            for (auto ii: what->rs()) right.emplace_back( host_to_json(ii));
            for (auto ii: what->rda()) right.emplace_back( host_to_json(ii));
            for (auto ii: what->rpc()) right.emplace_back( host_to_json(ii));

        }

        if(left.empty()) {
            left.emplace_back(jsonize::from((MitmHostCX*)nullptr, verbosity));
        }
        if(right.empty()) {
            right.emplace_back(jsonize::from((MitmHostCX*)nullptr, verbosity));
        }


        ret["oid"] = what->oid();

        ret["left"] = left;
        ret["right"] = right;


        if(verbosity > DIA) {
            ret["has_parent"] = { (what->parent() != nullptr) };
            ret["is_root"] = what->pollroot();
        }

        if(verbosity >= INF) {
            ret["policy"] = what->matched_policy();

            if(what->identity_resolved()) {
                ret["identity"] = { { "user",  what->identity()->username() },
                                    { "groups", what->identity()->groups() }
                };
            }

            ret["stats"]["speed"] = {
                    { "up_str", number_suffixed(what->stats().mtr_up.get() * 8) + "bps"},
                    { "down_str", number_suffixed(what->stats().mtr_down.get() * 8) + "bps"},
                    { "up", what->stats().mtr_up.get()},
                    { "down", what->stats().mtr_down.get()}
            };

            ret["stats"]["counters"] = {
                    { "bytes_up", what->stats().mtr_up.total() },
                    { "bytes_down", what->stats().mtr_down.total() }
            };

            ret["stats"]["flow"] = {
                    { "size", what->first_left() ? what->first_left()->flow().data().size() : 0 }
            };
        }



        return ret;
    }


    nlohmann::json from(MitmHostCX* what, int verbosity) {
        nlohmann::json ret;

        if(what) {
            auto h = what->host().empty() ? "0.0.0.0" : what->host();
            auto p = what->port().empty() ? "0" : what->port();
            auto c = what->com() ? what->com()->shortname() : "none";
            if(c.empty()) c = "unknown";

            ret["host"] = h;
            ret["port"] = p;
            ret["com"] = c;
        }
        else {
            ret["host"] = "0.0.0.0";
            ret["port"] = "0";
            ret["com"] = "none";
        }

        return ret;
    }
}
