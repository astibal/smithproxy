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

#include <regex>
#include <ctime>
#include <cerrno>
#include <chrono>
#include <thread>
#include <openssl/rand.h>

#include <proxy/mitmproxy.hpp>
#include <proxy/mitmhost.hpp>
#include <proxy/streamhandler.hpp>
#include <proxy/mitmproxy_utils.hpp>
#include <proxy/filters/filterproxy.hpp>
#include <proxy/filters/sinkhole.hpp>

#include <proxy/proxymaker.hpp>
#include <proxy/nbrhood.hpp>

#include <log/logger.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/webhooks.hpp>

#include <uxcom.hpp>
#include <staticcontent.hpp>

#include <traflog/fsoutput.hpp>
#include <service/tpool.hpp>

#include <algorithm>

#include <socle/common/base64.hpp>
#include <socle/timed_guard.hpp>

#include <inspect/fp/ja4.hpp>

using namespace socle;

MitmProxy::MitmProxy(baseCom* c): baseProxy(c), start_stop_tls_(*this) {

    current_sessions()++;
    total_sessions()++;
}

bool MitmProxy::stage_stream_handler(std::unique_ptr<sx::StreamHandler> handler) {
    if (!handler || stream_handler_) {
        return false;
    }

    stream_handler_ = std::move(handler);
    return true;
}

bool MitmProxy::activate_stream_handler() {
    if (!stream_handler_ || stream_handler_attached_) {
        return false;
    }

    tap();
    stream_handler_->observe_plaintext(
        [this](sx::stream_direction direction, std::string_view plaintext) {
            write_stream_traffic(direction, plaintext);
        });
    stream_handler_->observe_events(
        [this](sx::stream_direction direction, std::string_view event) {
            write_stream_event(direction, event);
        });
    if (!stream_handler_->attach(*this)) {
        stream_handler_->shutdown();
        state().dead(true);
        shutdown();
        return false;
    }

    // Keep the original descriptors as readiness notifications. Host contexts
    // remain io_disabled, while the handler consumes the shared socket stream
    // through its dup() descriptors.
    for (auto* cx : {first_left(), first_right()}) {
        if (!cx) continue;
        com()->set_poll_handler(cx->socket(), this);
        com()->set_monitor(cx->socket());
    }

    stream_handler_attached_ = true;
    return true;
}

bool MitmProxy::adopt_stream_handler(std::unique_ptr<sx::StreamHandler> handler) {
    return stage_stream_handler(std::move(handler)) && activate_stream_handler();
}

void MitmProxy::toggle_tlog () {

    if(not writer_opts()->write_payload) return;

    auto const& cfg = CfgFactory::get();

    // let pass further local.disabled and remote.enabled => writes only GRE packets using PCAP features
    if(not cfg->capture_local.enabled and not cfg->capture_remote.enabled) return;





    // create traffic logger if it doesn't exist
    if(not tlog_) {

        // A protocol adapter may transform a compatible logger. The core does
        // not inspect the transport or flow implementation behind that adapter.
        auto install_logger = [this](
                std::unique_ptr<socle::baseTrafficLogger> output) {
            if (traffic_log_adapter_) {
                output = traffic_log_adapter_->wrap(std::move(output));
            }
            tlog_ = std::move(output);
        };

        auto fmt = cfg->capture_local.format;

        switch (fmt.value) {
            case ContentCaptureFormat::type_t::SMCAP: {

                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                install_logger(std::make_unique<socle::traflog::SmcapLog>(this,
                                                                   CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   suf.c_str()));

                }
                break;

            case ContentCaptureFormat::type_t::PCAP: {
                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                auto pcaplog = std::make_unique<socle::traflog::PcapLog>(this,
                                                             CfgFactory::get()->capture_local.dir.c_str(),
                                                             CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                             suf.c_str(),
                                                             true);
                pcaplog->details.ttl = 32;
                CfgFactory::gre_export_apply(pcaplog.get());
                install_logger(std::move(pcaplog));

                }
                break;

            case ContentCaptureFormat::type_t::PCAP_SINGLE: {

                static std::once_flag once;
                std::call_once(once, [&fmt, &cfg] {
                    auto &single = socle::traflog::PcapLog::single_instance();
                    auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);

                    single.FS = socle::traflog::FsOutput(nullptr, cfg->capture_local.dir.c_str(),
                                                         cfg->capture_local.file_prefix.c_str(),
                                                         suf.c_str(), false);

                    single.FS.generate_filename_single("smithproxy", true);
                });

                // PCAP_SINGLE synthesizes packets through the shared logger,
                // so its remote exporter must reflect the current config too.
                // Applying this only during call_once leaves GRE detached when
                // capture settings are enabled or changed later.
                CfgFactory::gre_export_apply(
                    &socle::traflog::PcapLog::single_instance());

                auto suf = fmt.to_ext(CfgFactory::get()->capture_local.file_suffix);
                auto n = std::make_unique<socle::traflog::PcapLog>(this, CfgFactory::get()->capture_local.dir.c_str(),
                                                                   CfgFactory::get()->capture_local.file_prefix.c_str(),
                                                                   suf.c_str(),
                                                                   false);
                n->single_only = true;
                n->details.ttl = 32;

                CfgFactory::gre_export_apply(n.get());

                install_logger(std::move(n));

                }
                break;
        }
    }
    
    // check if we have there status file
    if(tlog_) {
        std::string data_dir = CfgFactory::get()->capture_local.dir;

        data_dir += "/disabled";
        
        struct stat st{};
        const int result = stat(data_dir.c_str(), &st);
        const bool present = (result == 0);
        
        if(present) {
            if(tlog()->status()) {
                _war("capture disabled by disabled-file");
            }
            tlog()->status(false);
        } else {
            if(! tlog()->status()) {
                _war("capture re-enabled from previous disabled-file state");
            }            
            tlog()->status(true);
        }
    }
}


MitmProxy::~MitmProxy() {
    
    if(writer_opts()->write_payload) {
        _deb("MitmProxy::destructor: syncing writer");

        for(auto const* cx: ls()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write(side_t::LEFT, cx->comlog());
                cx->comlog().clear();
            }
        }               
        
        for(auto const* cx: rs()) {
            if(! cx->comlog().empty()) {
                if(tlog()) tlog()->write_right(cx->comlog());
                cx->comlog().clear();
            }
        }         
        
        if(tlog()) tlog()->write_left("Connection stop\n");
    }


    if(not filters_.empty() and sx::http::webhooks::is_enabled()) {
        auto event = nlohmann::json();
        bool got_something = false;

        for (auto &[name, filter]: filters_) {
            if(filter->update_states()) {
                event[name] = filter->to_json(iINF);
                got_something = true;
            }
            else {
                _dia("filter %s did not profile any useful data for webhook", name.c_str());
            }
        }

        if(got_something) {
            sx::http::webhooks::send_action("connection-info", to_connection_ID(), event);
            _dia("webhook sent");
        } else {
            _dia("nothing to sent to webhook");
        }
    }

    current_sessions()--;
}

std::string MitmProxy::to_connection_label(bool force_resolve) const {
    auto const* left = first_left();
    auto const* right = first_right();

    std::stringstream ss;
    left ? ss << left->name(iINF, force_resolve) : ss << "0:0";
    ss << "+";
    right ? ss << right->name(iINF, force_resolve) : ss << "0:0";

    return sx::session_protocol_names(ss.str(), session_protocol());
}

std::string_view MitmProxy::session_protocol() const noexcept {
    return stream_handler_ ? stream_handler_->session_protocol() : std::string_view{};
}


std::string MitmProxy::to_connection_ID() const {
    return string_format("Proxy-%lX-PTR-%lX", StaticContent::boot_random,
                         reinterpret_cast<std::uintptr_t>(this));
}

void MitmProxy::webhook_session_start() const {
    if(not sx::http::webhooks::is_enabled() or wh_start) return;

    nlohmann::json j;
    auto cl = to_connection_label();
    j["info"] = { {"session", cl } };
    sx::http::webhooks::send_action("connection-start", to_connection_ID(), j);

    wh_start = true;
}

std::optional<std::string> MitmProxy::get_application() const {

    auto const* mh = first_left();
    if(not mh) return std::nullopt;

    std::string connection_protocol;
    auto app = mh->engine_ctx.application_data;

    if(app) {
        return app->protocol();
    }

    return std::nullopt;
}

void MitmProxy::webhook_session_stop() const {
    if(not sx::http::webhooks::is_enabled() or wh_stop) return;

    nlohmann::json j;
    auto cl = to_connection_label();

    uint64_t uB = 0L;
    uint64_t dB = 0L;
    std::optional<nlohmann::json> l7;
    std::optional<nlohmann::json> tls;

    auto const* l = first_left();
    if(l) {
        uB = l->meter_read_bytes;
        dB = l->meter_write_bytes;

        if(auto app = l->engine_ctx.application_data; app) {
            l7 =  { { "app", app->protocol() },
                    { "details", app->requests_all() },
                    { "signatures", l->matched_signatures() }
            };
            if(! app->custom_list_name().empty()) {
                l7.value()[app->custom_list_name()] = app->custom_list();
            }
        }
    }
    auto const* r = first_right();
    if(r){

        if(auto* scom = dynamic_cast<SSLCom*>(r->com()); scom) {
            nlohmann::json x;
            x["sni"] = scom->get_sni();
            tls = x;
        }
    }

    j["info"] = { {"session", cl },
                  {"policy", matched_policy() },
                  { "bytes_up", uB },
                  { "bytes_down", dB },
                  { "ja4_ch", ja4.ClientHello },
                  { "ja4_ch_ignore_sni", acct_opts.ja4_clienthello_ignore_sni },
                  { "ja4_sh", ja4.ServerHello },
    };

    if(tls.has_value())  j["info"]["tls"] = tls.value();
    if(l7.has_value())  j["info"]["l7"] = l7.value();



    sx::http::webhooks::send_action("connection-stop", to_connection_ID(), j);

    wh_stop = true;
}


std::string MitmProxy::to_string(int verbosity) const {
    std::stringstream r;
    if(verbosity >= INF) r <<  "MitM|";

    r << baseProxy::to_string(verbosity);
    
    if(verbosity >= INF) {
        r << string_format(" policy: %d ", matched_policy());

        if(stream_handler_) {
            r << string_format("%.*s:%s bytes up/dw: %llu/%lluB ",
                               static_cast<int>(stream_handler_->session_protocol().size()),
                               stream_handler_->session_protocol().data(),
                               stream_handler_->state().c_str(),
                               static_cast<unsigned long long>(stream_handler_->bytes_up()),
                               static_cast<unsigned long long>(stream_handler_->bytes_down()));
        }
        
        if(verbosity > INF) r << "\n    ";

        std::string const sp_str = number_suffixed(stats_.mtr_up.get()*8) + "/" + number_suffixed(stats_.mtr_down.get()*8);
        auto speed_str = (sp_str == "0.0/0.0") ? "up/dw: --" : string_format("up/dw: %s", sp_str.c_str());


        r << speed_str;
        
        if(verbosity > INF) { 
            r << string_format("\n    Policy  index: %d", matched_policy());


            if(matched_policy() >= 0) {
                auto p = CfgFactory::get()->db_policy_list.at(matched_policy());
                r << string_format("\n    Policy: %s", p->element_name().c_str());
            }


        }        
    }
    
    return sx::session_protocol_names(r.str(), session_protocol());
}


void MitmProxy::update_neighbors() {
    if(auto fl = first_left(); fl) {
        if(auto lhost = fl->chost(); not lhost.empty()) {
            auto &nbr = NbrHood::instance();

            nbr.update(first_left()->chost());
        }
    }
}



void MitmProxy::add_filter(std::string const& name, FilterProxy* fp) {
    filters_.emplace_back(name, fp);
    fp->init();
}


int MitmProxy::handle_sockets_once(baseCom* xcom) {

    webhook_session_start();

    // A policy stages the handler before the non-blocking upstream connect.
    // Activate it at the first worker cycle where the upstream is connected,
    // before baseProxy gets an opportunity to consume either SSH banner.
    if (stream_handler_ && !stream_handler_attached_ && !state().dead()) {
        auto* right = first_right();
        if (right && right->is_connected() && !activate_stream_handler()) {
            return 0;
        }
    }

    if (stream_handler_attached_ && !state().dead()) {
        using result_t = sx::StreamHandler::result;
        result_t result;

        // A handler reports progress when it changed state or consumed data
        // and can immediately do more work without another readiness event.
        // Drain such work now; waiting for a fresh epoll wakeup adds visible
        // latency and can deadlock protocols whose peer waits for our reply.
        do {
            result = stream_handler_->drive();
        } while (result == result_t::progress && !state().dead());

        if (result == result_t::finished
            || result == result_t::blocked
            || result == result_t::failed) {
            if (result != result_t::finished) {
                _war("stream handler %s in state %s: %s",
                     result == result_t::blocked ? "blocked" : "failed",
                     stream_handler_->state().c_str(),
                     stream_handler_->error().c_str());
            }
            stream_handler_->shutdown();
            state().dead(true);
            shutdown();
            return 0;
        }

        // Exclusive handlers own all stream I/O. The monitored host sockets
        // only wake this method; baseProxy must never consume their bytes.
        return 0;
    }

    return baseProxy::handle_sockets_once(xcom);
}


std::string whitelist_make_key_l4(baseHostCX const* cx)  {
    
    std::string key;
    
    if(cx != nullptr && cx->peer() != nullptr) {
        key = cx->host() + ":" + cx->peer()->host() + ":" + cx->peer()->port();
    } else {
        key = "?";
    }
    
    return key;
}

std::string whitelist_make_key_cert(baseHostCX const* cx) {
    if (not cx) return {};

    auto const* scom  = dynamic_cast<SSLCom*>(cx->peercom());
    if(not scom) return {};

    auto fg = SSLFactory::fingerprint(scom->target_cert());
    return fg;
}

std::string whitelist_make_key_override(baseHostCX const* cx,
                                        SSLCom const* peercom) {
    auto const l4_key = whitelist_make_key_l4(cx);
    if(l4_key.empty() || l4_key == "?" || !peercom) return {};

    auto const* client_com = dynamic_cast<SSLCom const*>(cx->com());
    if(!client_com) return {};
    return sx::mitmproxy::override_scope_key(l4_key, client_com->get_sni());
}

sx::mitmproxy::override_challenge_store& MitmProxy::override_challenges() {
    static sx::mitmproxy::override_challenge_store challenges(500);
    return challenges;
}


bool MitmProxy::is_white_listed(MitmHostCX const* mh, SSLCom* peercom) {

    auto const* scom = peercom ? peercom : dynamic_cast<SSLCom*>(mh->peercom());
    auto find_it = [&](auto key) -> bool {

        auto lc_ = std::scoped_lock(whitelist_verify().getlock());

        auto wh_entry = whitelist_verify().get(key);
        _dia("whitelist_verify[%s]: %s", key.c_str(), wh_entry ? "found" : "not found");

        // !!! wh might be already invalid here, unlocked !!!
        if (wh_entry != nullptr) {
            if(wh_entry->value().single_use) {
                whitelist_verify().erase(key);
                _dia("whitelist_verify[%s]: consumed single-use entry", key.c_str());
                return true;
            }
            if (scom->opt.cert.failed_check_override_timeout_type == 1) {
                auto const ttl = sx::mitmproxy::override_ttl_seconds(
                    scom->opt.cert.failed_check_override_timeout);
                if(!ttl) {
                    whitelist_verify().erase(key);
                    _war("whitelist_verify[%s]: invalid sliding timeout %d",
                         key.c_str(), scom->opt.cert.failed_check_override_timeout);
                    return false;
                }
                wh_entry->expired_at() = ::time(nullptr) + *ttl;
                _dia("whitelist_verify[%s]: timeout reset to %d", key.c_str(),
                     scom->opt.cert.failed_check_override_timeout);
            }
            return true;
        }

        return false;
    };

    // Browser-created overrides are scoped to the original client SNI. The
    // legacy L4 and certificate keys remain intentionally broad for explicit
    // operator CLI entries and client-certificate bypass.
    std::string key_override = whitelist_make_key_override(mh, scom);
    if (!key_override.empty() && find_it(key_override)) return true;

    // Look for operator/client-certificate whitelist entries.
    std::string key_l4 = whitelist_make_key_l4(mh);
    if ((not key_l4.empty()) and key_l4 != "?" and find_it(key_l4)) return true;

    std::string key_cert = whitelist_make_key_cert(mh);
    if ((not key_cert.empty()) and key_cert != "?" and find_it(key_cert)) return true;

    return false;
};


bool MitmProxy::handle_com_response_ssl(MitmHostCX* mh)
{
    // cast only once: in ja4 section, or later in code
    SSLCom* scom = nullptr;

    // check TLS ClientHello and calculate JA4, if allowed by options
    if(acct_opts.ja4_clienthello and ja4.ClientHello.empty() and ja4.clienthello_counter < ja4.max_reads) {

        // An empty or incomplete capture is independent of the certificate
        // decision below.  Keep retrying JA4 without marking all TLS response
        // handling complete.
        ja4.clienthello_counter++;
        scom = dynamic_cast<SSLCom *>(mh->peercom());
        auto const capture_action = sx::mitmproxy::hello_capture_next(
            scom != nullptr,
            scom ? scom->client_hello_buffer().size() : 0,
            5,
            ja4.clienthello_counter,
            ja4.max_reads);

        // we are always left context
        if (capture_action == sx::mitmproxy::hello_capture_action::parse) {
            sx::ja4::TLSClientHello ch;
            ch.ignore_sni = acct_opts.ja4_clienthello_ignore_sni;
            auto const &ch_buf = scom->client_hello_buffer();

            // yes, some copying :( - in c++20 is span, but we are still at c++17
            auto bufvec = std::vector(ch_buf.data() + 5, ch_buf.data() + ch_buf.size());
            if(ch.from_buffer(bufvec) == 0) {
                ja4.ClientHello = ch.ja4();
                _dia("JA4: %s (attempt %d)", ja4.ClientHello.c_str(), ja4.clienthello_counter);
            } else if(ja4.clienthello_counter >= ja4.max_reads) {
                acct_opts.ja4_clienthello = false;
            }

            // we will hijack serverhello here too, but we are OK to test only once
            if(acct_opts.ja4_serverhello and ja4.ServerHello.empty() and not scom->server_hello_buffer().empty()) {
                sx::ja4::TLSServerHello sh;
                auto const &sh_buf = scom->server_hello_buffer();

                // yes, some copying :( - in c++20 is span, but we are still at c++17
                auto shbufvec = std::vector(sh_buf.data(), sh_buf.data() + sh_buf.size());
                if(sh.from_buffer(shbufvec) == 0) {
                    ja4.ServerHello = sh.ja4();
                    _dia("JA4S: %s", ja4.ServerHello.c_str());
                }
            }
        }
        else if(capture_action == sx::mitmproxy::hello_capture_action::disable) {
            acct_opts.ja4_clienthello = false;
        }
    }

    if(ssl_handled) {
        return false;
    }

    // set scom if not set earlier
    if(! scom) {
        scom = dynamic_cast<SSLCom *>(mh->peercom());
        if(! scom) {
            // spare some cycles and avoid futile next calls
            // ssl_handled can then be reset manually if needed
            ssl_handled = true;
        }
    }

    bool redirected = false;

    auto const client_cert_action = scom
        ? sx::mitmproxy::client_certificate_next(
              scom->verify_bitcheck(SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ),
              scom->opt.cert.client_cert_action)
        : sx::mitmproxy::client_certificate_action::none;
    std::optional<bool> client_cert_was_whitelisted;
    bool client_cert_bypass_failed = false;

    if(scom && client_cert_action ==
                   sx::mitmproxy::client_certificate_action::whitelist_next) {
        // Action 2 means that the *next* connection bypasses interception so
        // the client can present its certificate directly. Do not let the
        // newly-created entry forgive an unrelated verification error on the
        // current connection.
        client_cert_was_whitelisted = is_white_listed(mh, scom);
        auto const ttl = sx::mitmproxy::override_ttl_seconds(
            scom->opt.cert.failed_check_override_timeout);
        auto const l4_key = whitelist_make_key_l4(mh);
        auto const valid_l4_key = !l4_key.empty() && l4_key != "?";
        if(!*client_cert_was_whitelisted && ttl && valid_l4_key) {
            log.event(INF, "%s connections whitelisted due to client cert bypass option",
                      l4_key.c_str());
            auto lc_ = std::scoped_lock(whitelist_verify().getlock());
            whitelist_verify_entry entry;
            entry.single_use = true;
            whitelist_verify().set(
                l4_key,
                new whitelist_verify_entry_t(
                    entry, *ttl));
        } else if(!*client_cert_was_whitelisted && (!ttl || !valid_l4_key)) {
            client_cert_bypass_failed = true;
            _war("client certificate bypass rejected: timeout=%d key=%s",
                 scom->opt.cert.failed_check_override_timeout,
                 l4_key.empty() ? "<empty>" : l4_key.c_str());
        }
    }

    if(scom && scom->is_verify_status_opt_allowed() &&
       client_cert_action != sx::mitmproxy::client_certificate_action::block &&
       !client_cert_bypass_failed) {

        // exceptions are satisfied and we can continue with proxying, regardless of other options

        ssl_handled = true;
        return false;
    }

    if(scom && client_cert_bypass_failed &&
       !scom->opt.cert.failed_check_replacement) {
        _war("client certificate bypass could not be prepared; closing fail-closed");
        state().dead(true);
        ssl_handled = true;
        return false;
    }

    if(scom && scom->opt.cert.failed_check_replacement) {

        auto const verification_failed = sx::mitmproxy::tls_verification_failed(
            static_cast<unsigned>(scom->verify_get()),
            static_cast<unsigned>(SSLCom::verify_status_t::VRF_OK),
            static_cast<unsigned>(SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ));
        auto const client_certificate_block =
            client_cert_action == sx::mitmproxy::client_certificate_action::block ||
            client_cert_bypass_failed;

        if(verification_failed || client_certificate_block) {

            if(tlog()) tlog()->write_left(
                client_certificate_block
                    ? "TLS peer requested a client certificate"
                    : "original TLS peer verification failed");

            bool const whitelist_found = client_cert_was_whitelisted
                ? *client_cert_was_whitelisted
                : is_white_listed(mh, scom);

            if(not whitelist_found) {
                _dia("relaxed cert-check: peer sslcom verify not OK, not in whitelist");

                // Prefer the application parser, but ALPN is already
                // authoritative before the first request bytes arrive.
                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_NONE) {
                    auto* client_ssl = dynamic_cast<SSLCom*>(mh->com());
                    SSLCom* peer_ssl = dynamic_cast<SSLCom*>(scom->peer());
                    std::string negotiated_alpn;
                    for(auto* candidate: {scom, peer_ssl, client_ssl}) {
                        if(candidate && negotiated_alpn.empty()) {
                            negotiated_alpn = candidate->negotiated_alpn();
                        }
                    }
                    if(negotiated_alpn == "h2") {
                        mh->replacement_type(MitmHostCX::REPLACETYPE_HTTP2);
                    } else if(negotiated_alpn == "http/1.1" || negotiated_alpn == "http/1.0") {
                        mh->replacement_type(MitmHostCX::REPLACETYPE_HTTP1);
                    }
                }

                if(mh->replacement_type() == MitmHostCX::REPLACETYPE_NONE) {
                    _war("certificate not OK; deferring replacement until client protocol is known");
                    tls_replacement_pending = true;
                    redirected = true;
                }
                else if(mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP1 ||
                        mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP2) {
                    _dia(" -> replacement: HTTP/%d - redirecting",
                         mh->replacement_type() == MitmHostCX::REPLACETYPE_HTTP2 ? 2 : 1);
                    mh->replacement_flag(MitmHostCX::REPLACE_BLOCK);
                    tls_replacement_pending = false;
                    redirected = true;
                    handle_replacement_ssl(mh);
                    
                } else {
                    _dia(" -> replacement unknown: killing proxy");
                    state().dead(true);
                }
            }
        }
    }

    if(!tls_replacement_pending) {
        ssl_handled = true;
    }

    return redirected;
}

bool MitmProxy::handle_cached_response(MitmHostCX* mh) {
    
    if(mh->inspection_verdict() == Inspector::CACHED) {

        if(tlog()) {
            tlog()->write_right("content has been served from cache\n");
            if(mh->inspection_verdict_response()) tlog()->write(side_t::RIGHT, *mh->inspection_verdict_response());
        }

        _dia("cached content: not proxying");
        return true;
    }
    
    return false;
}


void MitmProxy::proxy_dump_packet(side_t sid, buffer const& buf) {
    auto const& log = log_dump;

    constexpr size_t chunk_sz = 1024;
    size_t printed = 0;
    bool printed_all = false;
    unsigned int counter =  0;

    do {

        if(printed + chunk_sz >= buf.size()) {
            auto cur_buf = buf.view(printed, buf.size() - printed);

            _dia("mitmproxy::proxy-%c%s: \r\n%s", from_side(sid),
                 counter == 0 ? "" : string_format("/%d", counter).c_str(),
                 hex_dump(cur_buf, 4, arrow_from_side(sid), true, printed).c_str());

            printed_all = true;
            break;
        }  else {
            size_t const actual_chunk_sz = std::min(chunk_sz, buf.size() - printed);
            auto cur_buf = buf.view(printed, actual_chunk_sz);

            _dia("mitmproxy::proxy-%c%s: \r\n%s", from_side(sid),
                 string_format("/%d", counter).c_str(),
                 hex_dump(cur_buf, 4, arrow_from_side(sid), true, printed).c_str());

            printed += chunk_sz;
        }
        counter++;

    } while(printed < 20480);


    if(not printed_all) {
        _dia("mitmproxy::proxy-%c: <truncated>", from_side(sid));
    }
};

static std::string b64_encode(buffer &buffer) {
    return libbase64::encode<std::string, char, unsigned char, true>(buffer.data(), buffer.size());
}

static std::string b64_decode(std::string const& encoded) {
    return libbase64::decode<std::string, char, unsigned char, false>(encoded);
}



bool MitmProxy::content_webhook(baseHostCX* cx, side_t side, buffer& buffer) {

    auto& log = log_content;

    if(not sx::http::webhooks::is_enabled()) return false;
    if(not cx or buffer.empty()) return false;

    if(not writer_opts()->webhook_enable) return false;

    bool was_modified = false;

    nlohmann::json j;
    auto cl = to_connection_label();
    std::string encoded = b64_encode(buffer);
    j["info"] = {
        { "session", cl },
        { "side", string_format("%c", from_side(side)) },
        { "content", encoded }
    };

    sx::http::webhooks::send_action_wait("connection-content", to_connection_ID(), j, [&](sx::http::expected_reply r){
        if(r.has_value()) {
            auto reply = r.value();
            _dia("webhook content-replace: response %d", reply.response.first);

            if(reply.response.first >= 200 and reply.response.first < 300) {
                auto json_obj = nlohmann::json::parse(reply.response.second, nullptr, false);
                if(json_obj.is_discarded()) {
                    _err("MitmProxy::content_webhook: response body is invalid");
                }
                else {
                    if(json_obj.contains("action")) {
                        if(json_obj["action"] == "discard") {
                            // data sent to webhook shall be discarded
                            buffer.size(0);
                            was_modified = true;
                        }
                        else {
                            // catch-all code to decode response if present
                            if(json_obj.contains("content")) {
                                std::string body = json_obj["content"];
                                auto decoded = b64_decode(body);

                                _dia("webhook content-replace: received %dB of replacement data", decoded.size());
                                {
                                    auto& log = log_content_dump;
                                    _deb("webhook content-replace: replacement: %s\r\n",
                                         hex_dump((unsigned char*)decoded.data(), decoded.size(), 4, 0, true).c_str());
                                }

                                buffer.assign(decoded.data(), decoded.size());
                                was_modified = true;
                            }
                            else {
                                _dia("webhook content-replace: no replacement body received");
                            }
                        }
                    }
                }
            }
        }
    });

    return was_modified;
}

bool MitmProxy::handle_content_webhook(baseHostCX* from, baseHostCX* to, side_t side) {
    if(writer_opts()->webhook_lock_traffic) {

        if(from->com() and from->com()->l4_proto() == SOCK_STREAM) {
            if(from->com()->so_keepalive(from->socket()) == 0) {
                _deb("connection 'from' socket set to KEEPALIVE");
            }
            else {
                _err("connection 'from' ERROR socket set to KEEPALIVE");
            }
        }
        if(to->com() and to->com()->l4_proto() == SOCK_STREAM) {
            if (to->com()->so_keepalive(to->socket()) == 0) {
                _deb("connection 'to' socket set to KEEPALIVE");
            }
            else {
                _err("connection 'to' ERROR socket set to KEEPALIVE");
            }
        }

        constexpr unsigned max_attempts = 3;
        constexpr unsigned lock_timeout = 1000;
        for(unsigned attempt_no = 1; attempt_no < max_attempts; ++attempt_no) {

            // traffic with applied webhook with enabled locking will block here
            auto lc_ = socle::threads::timed_guard(MitmProxy::Opts_ContentWriter::webhook_content_lock,
                                                   std::chrono::milliseconds(lock_timeout));
            if (not lc_.owns_lock()) {
                _war("[%s]: content_webhook: waiting for other content webhook to finish (attempt %d)",
                     to_string(iNOT).c_str(), attempt_no);
                log.event(WAR, "[%s]: content_webhook: waiting for other content webhook to finish (attempt %d)",
                     to_string(iNOT).c_str(), attempt_no);
            }
            else {
                if(attempt_no > 1) {
                    _war("[%s]: content_webhook: webhook is ready now (attempt %d)",
                         to_string(iNOT).c_str(), attempt_no);
                    log.event(WAR, "[%s]: content_webhook: webhook is ready now (attempt %d)",
                         to_string(iNOT).c_str(), attempt_no);

                }
                return content_webhook(from, side, from->to_read());
            }
        }
        _err("[%s]: content_webhook: previous webhook takes too long to complete, content NOT sent to webhook.",
             to_string(iNOT).c_str());
        log.event(ERR, "[%s]: content_webhook: previous webhook takes too long to complete, content NOT sent to webhook.",
             to_string(iNOT).c_str());

    }
    else {
        return content_webhook(from, side, from->to_read());
    }
    return false;
}

void MitmProxy::proxy(baseHostCX* from, baseHostCX* to, side_t side, bool redirected,
                      bool consume_source) {

    if(not to or not from or from->to_read().empty()) return;

    if(redirected) {
        if(tls_replacement_pending) {
            // Upstream application data must not reach the client after a
            // failed certificate decision. Keep the client leg alive until
            // its first application frame identifies the response protocol.
            from->to_read().clear();
            return;
        }
        // The replacement is queued on the client (left) context. When this
        // decision was triggered by upstream bytes, `to` is that client and
        // shutting it down discards our own queued response. Always retire
        // the upstream context and let the client drain its write queue.
        auto* upstream = side == side_t::RIGHT ? from : to;
        upstream->shutdown();
        return;
    }

    // 1. content webhook first (potentially modifies from->to_read() buffer
    if(writer_opts()->webhook_enable) {
        auto orig_sz = from->to_read().size();
        if(handle_content_webhook(from, to, side)) {
            auto sz = from->to_read().size();
            _dia("mitmproxy::proxy-%c: %dB replaced with %dB (webhook)", from_side(side), orig_sz, sz);
        }
    }

    // 2. do filtering (stats, access, etc.)
    for(auto const& [ filter_name, filter_proxy ]: filters_) {

        _deb("MitmProxy::proxy: running filter %s", filter_name.c_str());
        filter_proxy->proxy(from, to, side, redirected);

        if(state().dead()) {
            _deb("MitmProxy::proxy: filter %s: proxy marked dead", filter_name.c_str());

            // after marking dead, session is not getting on_error anymore
            webhook_session_stop();
            shutdown();
            return;
        }
    }

    // 3. perform replacement according to config content rules
    std::optional<buffer> replacement;
    if (content_rule() != nullptr and not content_rule()->empty()) {
        replacement = content_replace_apply(from->to_read());
    }
    if(*log_dump.level() >= iDIA) {
        // std::optional::value_or() returns a value. Using it here used to
        // copy the complete plaintext buffer solely for a diagnostic dump.
        auto const& dump_buffer = replacement ? *replacement : from->to_read();
        proxy_dump_packet(side, dump_buffer);
    }

    if(replacement.has_value()) {
        to->to_write(replacement.value());
        write_traffic_log(side, from, &replacement.value());

        auto orig_sz = from->to_read().size();
        auto sz = replacement.value().size();
        _dia("mitmproxy::proxy-%c: %dB replaced with %dB (content rule)", from_side(side), orig_sz, sz);
    }
    else {
        write_traffic_log(side, from);
        to->to_write(from->to_read(), consume_source);

        auto sz = from->to_read().size();
        auto fastlane = sz > 0 and from->to_read().empty();
        _dia("mitmproxy::proxy-%c: %dB copied %s", from_side(side), sz, fastlane ? "(fastlane)": "");
    }

}


void MitmProxy::write_traffic_log(side_t side, baseHostCX* cx, buffer* custom_buffer) {

    if(writer_opts()->write_payload) {
        if(not cx) return;

        auto* buffer = custom_buffer;
        if(not buffer) {
            buffer = &cx->to_read();
        }

        toggle_tlog();

        if(! cx->comlog().empty()) {
            if(tlog()) tlog()->write(side, cx->comlog());
            cx->comlog().clear();
        }

        if(tlog()) tlog()->write(side, *buffer);
    }
}

void MitmProxy::write_stream_traffic(sx::stream_direction direction,
                                     std::string_view plaintext) {
    if(!writer_opts()->write_payload || plaintext.empty()) return;

    toggle_tlog();
    if(!tlog()) return;

    buffer payload(plaintext.data(), plaintext.size());
    tlog()->write(direction == sx::stream_direction::upstream
                      ? side_t::LEFT : side_t::RIGHT,
                  payload);
}

void MitmProxy::write_stream_event(sx::stream_direction direction,
                                   std::string_view event) {
    if(!writer_opts()->write_payload || event.empty()) return;
    toggle_tlog();
    if(!tlog()) return;
    tlog()->write_annotation(direction == sx::stream_direction::upstream
                                 ? side_t::LEFT : side_t::RIGHT,
                             std::string(event));
}

void MitmProxy::on_left_bytes(baseHostCX* cx) {

    if(not cx or state().dead()) return;

    bool redirected = handle_requirements(cx);

    if(tls_replacement_pending) {
        auto* mh = MitmHostCX::from_baseHostCX(cx);
        if(mh && mh->replacement_type() == MitmHostCX::REPLACETYPE_NONE) {
            _war("certificate not OK on non-HTTP TLS protocol - dropping proxy");
            tls_replacement_pending = false;
            ssl_handled = true;
            state().dead(true);
            return;
        }
    }

    //update meters
    total_mtr_up().update(cx->to_read().size());
    if(acct_opts.details) {
        NbrHood::instance().apply(cx->host(), [&cx](Neighbor& nbr) {
            nbr.last_seen = time(nullptr);
            if(not nbr.timetable.empty()) {
                nbr.timetable[0].bytes_up += cx->to_read().size();
            }
            return true;
        });
    }

    auto destinations_remaining = right_sockets.size() + right_delayed_accepts.size();

    // Preserve the source for every destination except the final one. The
    // final transfer may retain the zero-copy fastlane swap.
    std::for_each(
            right_sockets.begin(),
            right_sockets.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::LEFT, redirected,
                          destinations_remaining == 1);
                    --destinations_remaining;
                }
            });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            right_delayed_accepts.begin(),
            right_delayed_accepts.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::LEFT, redirected,
                          destinations_remaining == 1);
                    --destinations_remaining;
                }
            });

}


bool MitmProxy::handle_requirements(baseHostCX* cx) {

    bool redirected = false;

    auto* mh = MitmHostCX::from_baseHostCX(cx);

    if(mh != nullptr) {

        // check com responses
        redirected = handle_com_response_ssl(mh);

    }

    return redirected;
}

void MitmProxy::on_right_bytes(baseHostCX* cx) {

    if(not cx or state().dead()) return;

    bool redirected = handle_requirements(cx->peer());

    // update total meters
    total_mtr_down().update(cx->to_read().size());

    if(acct_opts.details) {
        if(auto fr = first_left(); fr) {
            NbrHood::instance().apply(fr->host(), [&cx](Neighbor &nbr) {
                nbr.last_seen = time(nullptr);
                if(not nbr.timetable.empty()) {
                    nbr.timetable[0].bytes_down += cx->to_read().size();
                }
                return true;
            });
        }
    }

    auto destinations_remaining = left_sockets.size() + left_delayed_accepts.size();

    std::for_each(
            left_sockets.begin(),
            left_sockets.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::RIGHT, redirected,
                          destinations_remaining == 1);
                    --destinations_remaining;
                }
            });

    // because we have left bytes, let's copy them into all right side sockets!
    std::for_each(
            left_delayed_accepts.begin(),
            left_delayed_accepts.end(),
            [&](auto* to) {
                if(not state().dead()) {
                    proxy(cx, to, side_t::RIGHT, redirected,
                          destinations_remaining == 1);
                    --destinations_remaining;
                }
            });

}


void MitmProxy::_debug_zero_connections(baseHostCX* cx) {

    if(cx->meter_write_count == 0 && cx->meter_write_bytes == 0 ) {
        auto* xcom = dynamic_cast<SSLCom*>(cx->com());
        if(xcom) {
            xcom->log_profiling_stats(iINF);

            int s = cx->socket();
            if(s == 0) s = cx->closed_socket();
            if(s != 0) {
                buffer b(1024);
                auto p = cx->com()->peek(s,b.data(),b.capacity(),0);
                _inf("        cx peek size %d", p);
            }
            
        }
        
        if(cx->peer()) {
            auto* xcom_peer = dynamic_cast<SSLCom*>(cx->peer()->com());
            if(xcom_peer) {
                xcom_peer->log_profiling_stats(iINF);
                _inf("        peer transferred bytes: up=%d/%dB dw=%d/%dB", cx->peer()->meter_read_count, cx->peer()->meter_read_bytes,
                                                                cx->peer()->meter_write_count, cx->peer()->meter_write_bytes);
                int s = cx->peer()->socket();
                if(s == 0) s = cx->peer()->closed_socket();
                if(s != 0) {
                    buffer b(1024);
                    auto p = cx->peer()->com()->peek(s,b.data(),b.capacity(),0);
                    _inf("        peer peek size %d", p);
                }                
            }
            
        }
    }
}


void MitmProxy::on_half_close(baseHostCX* cx) {
    if(sx::mitmproxy::half_close_peer_can_drain(cx)) {
        // We have a live peer with a non-zero write queue: set hold timer.
        if(half_holdtimer > 0) {
            
            // we count timer already!
            long expiry = half_holdtimer + half_timeout() - ::time(nullptr);
            
            if(expiry > 0) {
                _ext("on_half_close: live peer with pending data: keeping up for %ds", expiry);
            } else {
                _dia("on_half_close: timer's up (%ds) - closing.", expiry);
                state().dead(true);
            }
            
            
        } else {
            _dia("on_half_close: live peer with pending data: keeping up for %ds", half_timeout);
            half_holdtimer = ::time(nullptr);
        }
        
    } else {
        // if peer doesn't exist or peercom doesn't exit, mark proxy dead -- no one to speak to
        _dia("on_half_close: peer with pending write-data is dead.");
        state().dead(true);
    }
}


std::string get_connection_details_str(MitmProxy* px, baseHostCX* cx, char side) {

    if(!cx) {
        return "";
    }

    std::string flags;
    flags += side;

    auto* mh = MitmHostCX::from_baseHostCX(cx);

    if(side == 'R' && cx->peer())
        mh = MitmHostCX::from_baseHostCX(cx->peer());

    if (mh != nullptr && mh->inspection_verdict() == Inspector::CACHED) flags+="C";

    std::stringstream detail;

    if(cx->peercom()) {
        auto* sc = dynamic_cast<SSLMitmCom*>(cx->peercom());
        if(sc) {
            detail << string_format("sni=%s ", sc->get_sni().c_str());
        }
    }
    if(mh && mh->engine_ctx.application_data) {

        auto* app = dynamic_cast<sx::engine::http::app_HttpRequest*>(mh->engine_ctx.application_data.get());
        if(app) {
            detail << "app=" << app->http_data.proto << app->http_data.host << " ";
        }
        else {
            detail << "app=" << mh->engine_ctx.application_data->str() << " ";
        }
    }

    std::string px_flags;

    if(px) {
        if(px->com()) {
            px_flags = px->com()->full_flags_str();
        }
    }

    detail << string_format("up=%d/%dB dw=%d/%dB flags=%s+%s",
                            cx->meter_read_count, cx->meter_read_bytes,
                            cx->meter_write_count, cx->meter_write_bytes,
                            flags.c_str(),
                            px_flags.c_str()
    );

    return detail.str();
}


void MitmProxy::on_error(baseHostCX* cx, char side, const char* side_label) {

    auto _log_closed_on = [&](loglevel const& level, const char* state_str) {

        // don't log already dead connections
        if(state().dead()) return;

        _if_level(level) {
            std::stringstream msg;
            msg << "Connection " << side_label << " " << state_str << "on ";

            if(state().error_on_left_read) msg << "Lr";
            if(state().error_on_left_write) msg << "Lw";
            if(state().error_on_right_read) msg << "Rr";
            if(state().error_on_right_write) msg << "Rw";

            if(cx) {
                msg << ": "
                    << get_connection_details_str(this, cx, side);
            }
            auto str = msg.str();
            log.log(level, log.topic(), "%s", str.c_str());
        }
    };
    auto _log_closed = [&](loglevel const& level) {
        _if_level(level) {

            // don't log already dead connections
            if(state().dead()) return;

            if(not cx) {
                _log_closed_on(ERR, "null cx");
                return;
            }

            std::stringstream msg;
            msg << "Connection from " << cx->full_name(side) << " closed: " << get_connection_details_str(this, cx, side);
            if(! replacement_msg.empty() ) {
                msg << ", replaced: " << replacement_msg;
            }
            auto str = msg.str();
            log.log(level, log.topic(), "%s", str.c_str());
        }
        _if_level(DEB) { _debug_zero_connections(cx); }
    };

    if(cx == nullptr) {
        _log_closed_on(ERR, "null cx");

        state().dead(true);
        return;
    }

    // if not dead (yet), do some cleanup/logging chores
    if( !state().dead()) {

        // don't waste time on low-effort delivery stuff, just get rid of it now.
        if(com()->l4_proto() == SOCK_DGRAM) {
            state().dead(true);
        }
        else if(cx->read_eof()) {
            auto* peer = cx->peer();
            if(peer && peer->com() && peer->com()->descriptor_valid(peer->socket())) {
                // A peer may close only its sending half after a complete
                // request and continue waiting for a delayed response. Keep
                // both remaining directions alive for the bounded grace
                // period even when the request queue has already drained.
                if(half_holdtimer == 0) half_holdtimer = ::time(nullptr);
                _log_closed_on(DIA, "half-closing");
                if(!peer->writebuf()->empty()) {
                    com()->set_write_monitor(peer->socket());
                }
            } else {
                _log_closed_on(DIA, "half-closing, peer dead");
                state().dead(true);
            }
        }
        else {
            // STREAM sockets need a bit of caring if still having a peer
            if(cx->peer()) {
                if(! cx->peer()->writebuf()->empty()) {

                    // do half-closed actions, and mark proxy dead if needed
                    on_half_close(cx);

                    if (state().dead()) {
                        // status dead is new, since we check dead status at the beginning
                        _log_closed_on(INF, "half-closed");

                    } else {
                        // on_half_close did not mark it dead, yet
                        _log_closed_on(DIA, "half-closing");

                        // provoke write to the peer's socket (could be superfluous)
                        com()->set_write_monitor(cx->peer()->socket());
                    }
                } else {

                    // duplicate code to DEAD before calling us

                    _if_level(INF) {
                        std::stringstream msg;
                        msg << "Connection from " << cx->full_name(side)
                            << " closed: "
                            << get_connection_details_str(this, cx, side);

                        if (!replacement_msg.empty()) {
                            msg << ", dropped: "
                                << replacement_msg;

                            _inf("%s", msg.str().c_str()); // log to generic logger
                        }
                        _inf("%s", msg.str().c_str());
                    }
                    state().dead(true);
                }
            } else {
                _log_closed_on(DIA, "half-closing, peer dead");
                state().dead(true);
            }
        }
    } else {
        // DEAD before calling us!
        // maybe even dead or unnecessary code

        if(cx->peer() && cx->peer()->writebuf()->empty()) {
            _log_closed(INF);

            state().dead(true);
        }
    }


    // state could change. Log if we are dead now
    if(state().dead()){
        if (writer_opts()->write_payload) {
            toggle_tlog();
            if (tlog()) {

                std::stringstream ss;
                ss << std::string(side_label) << "side connection closed: " << cx->name() << "\n";
                auto msg = ss.str();

                tlog()->write(to_side(side), msg);
                if (!replacement_msg.empty()) {
                    tlog()->write(to_side(side), cx->name() + "   dropped by proxy:" + replacement_msg + "\n");
                }
            }
        }

        webhook_session_stop();
    }
}

void MitmProxy::on_left_error(baseHostCX* cx) {
    on_error(cx, 'L', "client");

}

void MitmProxy::on_right_error(baseHostCX* cx) {
    on_error(cx, 'R', "server");

}

bool MitmProxy::run_timers() {
    auto ret = baseProxy::run_timers();

    if(ret && !state().dead() &&
       sx::mitmproxy::half_close_grace_expired(
           half_holdtimer, half_timeout(), std::time(nullptr))) {
        _dia("half-close drain grace expired; closing proxy");
        state().dead(true);
    }

    // run timers actually crawled children
    if(ret and state().dead()) {
        if (writer_opts()->write_payload) {
            toggle_tlog();
            if (tlog()) {

                std::stringstream ss;
                ss << "connection timed out\n";
                auto msg = ss.str();

                tlog()->write(to_side('L'), msg);
            }
        }

        webhook_session_stop();
    }

    return ret;
}



std::string MitmProxy::verify_flag_string(int code) {

    using verify_status_t = SSLCom::verify_status_t;

    switch(code) {
        case verify_status_t::VRF_OK:
            return "Certificate verification successful";
        case verify_status_t::VRF_SELF_SIGNED:
            return "Target certificate is self-signed";
        case verify_status_t::VRF_SELF_SIGNED_CHAIN:
            return "Server certificate's chain contains self-signed, untrusted CA certificate";
        case verify_status_t::VRF_UNKNOWN_ISSUER:
            return "Server certificate is issued by untrusted certificate authority";
        case verify_status_t::VRF_CLIENT_CERT_RQ:
            return "Server is asking client for a certificate";
        case verify_status_t::VRF_REVOKED:
            return "Server's certificate is REVOKED";
        case verify_status_t::VRF_HOSTNAME_FAILED:
            return "Client application asked for SNI server is not offering";
        case verify_status_t::VRF_INVALID:
            return "Certificate is not valid";
        case verify_status_t::VRF_ALLFAILED:
            return "It was not possible to obtain certificate status";
        case verify_status_t::VRF_CT_MISSING:
            return "Certificate Transparency info is missing";
        case verify_status_t::VRF_CT_FAILED:
            return "Certificate Transparency verification failed";
        default:
            return string_format("code 0x%04x", code);
    }
}

std::string MitmProxy::verify_flag_string_extended(int code) {

    using verify_status_t = SSLCom::vrf_other_values_t;

    switch(code) {
        case verify_status_t::VRF_OTHER_SHA1_SIGNATURE:
            return "Issuer certificate is signed using SHA1 (considered insecure).";
        case verify_status_t::VRF_OTHER_CT_INVALID:
            return "Certificate Transparency tag is INVALID.";
        case verify_status_t::VRF_OTHER_CT_FAILED:
            return "Unable to verify Certificate Transparency tag.";
        default:
            return string_format("extended code 0x%04x", code);
    }
}

void MitmProxy::set_replacement_msg_ssl(SSLCom* scom) {

    using verify_status_t = SSLCom::verify_status_t;

    if(scom && scom->verify_get() != verify_status_t::VRF_OK) {

        std::stringstream  ss;

        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_SELF_SIGNED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_SELF_SIGNED_CHAIN) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_UNKNOWN_ISSUER) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_CLIENT_CERT_RQ) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_REVOKED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_REVOKED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_HOSTNAME_FAILED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_HOSTNAME_FAILED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_INVALID)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_INVALID) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_ALLFAILED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_ALLFAILED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_MISSING)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_CT_MISSING) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_FAILED)) {
            ss << "(ssl:" << verify_flag_string(verify_status_t::VRF_CT_FAILED) << ")";
        }
        if(scom->verify_bitcheck(verify_status_t::VRF_EXTENDED_INFO)) {

            for(auto const& ei: scom->verify_extended_info()) {
                ss << "(ssl: " << verify_flag_string(ei) << ")";
            }
        }
        replacement_msg += ss.str();
    }
}

std::string MitmProxy::replacement_ssl_verify_detail(SSLCom* scom) {

    using verify_status_t = SSLCom::verify_status_t;

    std::stringstream ss;
    if(!scom) return {};

    int reason_count = 1;
    auto add_reason = [&](std::string const& detail, bool critical = false) {
        ss << "<section class=\"reason" << (critical ? " reason-critical" : "")
           << "\"><h3>Reason " << reason_count++ << "</h3><p>"
           << sx::mitmproxy::html_escape(detail) << "</p></section>";
    };

    if(scom->verify_get() != verify_status_t::VRF_OK) {
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED))
            add_reason(verify_flag_string(verify_status_t::VRF_SELF_SIGNED) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN))
            add_reason(verify_flag_string(verify_status_t::VRF_SELF_SIGNED_CHAIN) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER))
            add_reason(verify_flag_string(verify_status_t::VRF_UNKNOWN_ISSUER) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ))
            add_reason(verify_flag_string(verify_status_t::VRF_CLIENT_CERT_RQ) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_REVOKED))
            add_reason(verify_flag_string(verify_status_t::VRF_REVOKED) +
                       ". The certificate has been revoked. Do not continue.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_MISSING))
            add_reason(verify_flag_string(verify_status_t::VRF_CT_MISSING) +
                       ". For a public service, do not continue unless this is expected.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_CT_FAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_CT_FAILED) +
                       ". Do not continue unless you understand the risk.", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_INVALID))
            add_reason(verify_flag_string(verify_status_t::VRF_INVALID) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_HOSTNAME_FAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_HOSTNAME_FAILED) + ".");
        if(scom->verify_bitcheck(verify_status_t::VRF_ALLFAILED))
            add_reason(verify_flag_string(verify_status_t::VRF_ALLFAILED) + ".", true);
        if(scom->verify_bitcheck(verify_status_t::VRF_EXTENDED_INFO)) {
            for(auto const& ei: scom->verify_extended_info())
                add_reason(verify_flag_string_extended(ei));
        }
    }

    if(reason_count == 1) {
        add_reason(string_format("No detailed problem description is available (code 0x%x).",
                                 scom->verify_get()));
    }

    return ss.str();
}


std::string MitmProxy::replacement_ssl_page(SSLCom* scom, sx::engine::http::app_HttpRequest const* app_request, std::string const& more_info) {
    // TODO: enrich this page with a structured summary of the original peer
    // certificate and the exact failed checks. Keep that reporting work
    // separate from protocol-correct replacement handling.

    if(!app_request) return {};

    return html()->render_tls_replacement(
        sx::mitmproxy::html_escape(app_request->http_data.proto +
                                   app_request->http_data.host),
        replacement_ssl_verify_detail(scom), more_info);
}

bool MitmProxy::write_replacement_response(MitmHostCX* cx,
                                           std::string const& body,
                                           unsigned status) {
    if(!cx) return false;

    auto* app_request = dynamic_cast<sx::engine::http::app_HttpRequest*>(
        cx->engine_ctx.application_data.get());
    bool const head_only = app_request && app_request->http_data.method == "HEAD";

    if(cx->replacement_type() == MitmHostCX::REPLACETYPE_HTTP2) {
        auto* connection = std::any_cast<sx::engine::http::v2::Http2Connection>(
            &cx->engine_ctx.state_data);
        auto const stream_id = connection ? connection->latest_request_stream_id : -1;
        if(stream_id > 0) {
            auto response = sx::engine::http::v2::make_response(
                stream_id, body, status, head_only);
            if(!response) return false;
            response->append(sx::engine::http::v2::make_goaway(
                static_cast<uint32_t>(stream_id), 0));
            cx->to_write(*response);
        } else {
            auto goaway = sx::engine::http::v2::make_server_preamble();
            goaway.append(sx::engine::http::v2::make_goaway(
                0, 0x0c, "TLS certificate rejected"));
            cx->to_write(goaway);
        }
        return true;
    }

    if(cx->replacement_type() == MitmHostCX::REPLACETYPE_HTTP1) {
        cx->to_write(html()->render_server_response(body, status, head_only));
        return true;
    }

    return false;
}

void MitmProxy::handle_replacement_ssl(MitmHostCX* cx) {

    if(tlog()) tlog()->write_left("TLS content replacement\n");

    auto* scom = dynamic_cast<SSLCom*>(cx->peercom());
    if(!scom) {
        std::string error("<html><head></head><body><p>Internal error</p><p>com object is not ssl-type</p></body></html>");
        write_replacement_response(cx, error, 500);
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);

        _err("cannot handle replacement for TLS, com is not SSLCom");
        
        return;
    }


    auto* app_request = dynamic_cast<sx::engine::http::app_HttpRequest*>(cx->engine_ctx.application_data.get());
    if(app_request != nullptr) {
        log.event(INF, "[%s]: HTTP replacement active", socle::com::ssl::connection_name(scom, true).c_str());

        auto find_orig_uri = [&]() -> std::optional<std::string> {
            auto const encoded = sx::mitmproxy::query_parameter(
                app_request->http_data.params, "orig_url");
            return encoded ? sx::mitmproxy::decode_relative_target(*encoded)
                           : std::nullopt;
        };


        auto generate_block_override = [&]() -> std::string {
            std::stringstream block_override;

            if (scom->opt.cert.failed_check_override) {
                auto const whitelist_ttl = sx::mitmproxy::override_ttl_seconds(
                    scom->opt.cert.failed_check_override_timeout);
                if(!whitelist_ttl) {
                    _err("cannot offer TLS override with invalid timeout %d",
                         scom->opt.cert.failed_check_override_timeout);
                    return {};
                }
                unsigned char random_bytes[16];
                if(RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
                    _err("cannot generate TLS override challenge");
                    return {};
                }

                static constexpr char hex[] = "0123456789abcdef";
                std::string token;
                token.reserve(sizeof(random_bytes) * 2);
                for(auto byte: random_bytes) {
                    token.push_back(hex[byte >> 4]);
                    token.push_back(hex[byte & 0x0f]);
                }

                const std::string challenge_key =
                    whitelist_make_key_override(cx, scom);
                if(!cx->peer() || challenge_key.empty()) {
                    _err("cannot offer TLS override without client TLS identity");
                    return {};
                }
                block_override
                    << R"(<form action="/SM/IT/HP/RO/XY/override/)"
                    << token << R"(" method="get">)";
                if (not app_request->http_data.uri.empty()) {
                    block_override
                        << R"(<input type="hidden" name="orig_url" value=")"
                        << sx::mitmproxy::html_escape(find_orig_uri().value_or("/"))
                        << R"(">)";
                }
                block_override
                    << R"(<input type="submit" value="Override" class="btn-red"></form>)";

                override_challenges().issue(
                    challenge_key, token, std::time(nullptr), 120);
            }

            return block_override.str();
        };

        auto const replacement_route = sx::mitmproxy::classify_replacement_route(
            app_request->http_data.uri);

        if(replacement_route == sx::mitmproxy::replacement_route::override_action) {
            
            // PHASE IV.
            // perform override action
                
                        
            if(scom->opt.cert.failed_check_override) {
            
                _dia("ssl_override: ph4 - asked for verify override for %s", whitelist_make_key_l4(cx).c_str());
                
                const auto supplied_token = sx::mitmproxy::override_token_from_route(
                    app_request->http_data.uri);
                const auto challenge_key = whitelist_make_key_override(cx, scom);
                const bool challenge_valid = override_challenges().consume(
                    challenge_key, supplied_token, std::time(nullptr));

                if(!challenge_valid) {
                    std::string error("<html><head></head><body><p>Failed to override</p><p>Action is invalid or expired.</p></body></html>");
                    write_replacement_response(cx, error, 403);
                    cx->close_after_write(true);
                    set_replacement_msg_ssl(scom);
                    replacement_msg += "(ssl: invalid override challenge)";
                    _war("Connection from %s: rejected invalid TLS override challenge",
                         cx->full_name('L').c_str());
                    return;
                }

                const std::string orig_url = find_orig_uri().value_or("/");
                const std::string escaped_orig_url = sx::mitmproxy::html_escape(orig_url);

                std::string override_applied = string_format(
                        R"(<html><head><meta http-equiv="Refresh" content="0; url=%s"></head><body><!-- applied, redirecting back to %s --></body></html>)",
                                                            escaped_orig_url.c_str(), escaped_orig_url.c_str());

                {
                    auto lc_ = std::scoped_lock(whitelist_verify().getlock());
                    auto const ttl = sx::mitmproxy::override_ttl_seconds(
                        scom->opt.cert.failed_check_override_timeout);
                    if(!ttl) {
                        std::string error("<html><head></head><body><p>Failed to override</p><p>Override timeout is invalid.</p></body></html>");
                        write_replacement_response(cx, error, 403);
                        cx->close_after_write(true);
                        set_replacement_msg_ssl(scom);
                        replacement_msg += "(ssl: invalid override timeout)";
                        return;
                    }
                    whitelist_verify().set(challenge_key,
                                           new whitelist_verify_entry_t({}, *ttl));
                }
                
                write_replacement_response(cx, override_applied);
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override)";
                
                _war("Connection from %s: SSL override activated for %s", cx->full_name('L').c_str(), app_request->request().c_str());
                
                return;
                
            } else {
                // override is not enabled, but client somehow reached this (attack?)
                std::string error("<html><head></head><body><p>Failed to override</p><p>Action is denied.</p></body></html>");
                write_replacement_response(cx, error, 403);
                cx->close_after_write(true);
                set_replacement_msg_ssl(scom);
                replacement_msg += "(ssl: override disabled)";
                
                return;
            }
            
        } else 
        if(replacement_route == sx::mitmproxy::replacement_route::warning){
            
            // PHASE III.
            // display warning and button which will trigger override
        
            _dia("ssl_override: ph3 - warning replacement for %s", whitelist_make_key_l4(cx).c_str());
            
            const std::string repl = replacement_ssl_page(scom, app_request, generate_block_override());

            write_replacement_response(cx, repl, 403);
            set_replacement_msg_ssl(scom);
            cx->close_after_write(true);
        } else 
        if(app_request->http_data.uri == "/"){
            // PHASE II
            // redir to warning message
            
            _dia("ssl_override: ph2 - redir to warning replacement for  %s", whitelist_make_key_l4(cx).c_str());
            
            std::string repl = R"(<html><head><meta http-equiv="Refresh" content="0; url=/SM/IT/HP/RO/XY/warning?q=1"></head><body></body></html>)";
            write_replacement_response(cx, repl, 403);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }   
        else {
            // PHASE I
            // redirecting to / -- for example some subpages would be displayed incorrectly
            
            _dia("ssl_override: ph1 - redir to / for %s", whitelist_make_key_l4(cx).c_str());
            
            const std::string redir_pre(R"(<html><head><script>top.location.href=")");
            const std::string redir_suf(R"(";</script></head><body></body></html>)");
            std::string original_target = app_request->http_data.uri;
            if(!app_request->http_data.params.empty()) {
                original_target += "?" + app_request->http_data.params;
            }

            std::string repl = redir_pre + "/SM/IT/HP/RO/XY/warning?q=1&orig_url=" +
                               sx::mitmproxy::query_encode(original_target) + redir_suf;
            write_replacement_response(cx, repl, 403);
            cx->close_after_write(true);
            set_replacement_msg_ssl(scom);
        }
    }

    else {
        _dia("ssl_override: enforced ph1 - redir to / for %s", whitelist_make_key_l4(cx).c_str());
        _inf("readbuf: \n%s", hex_dump(cx->readbuf(), 4).c_str());

        log.event(INF, "[%s]: enforced HTTP replacement active", socle::com::ssl::connection_name(scom, true).c_str());

        const std::string redir_pre("<html><head><script>top.location.href=\"");
        const std::string redir_suf("\";</script></head><body></body></html>");


        std::string repl = redir_pre + "/" + redir_suf;
        write_replacement_response(cx, repl, 403);
        cx->close_after_write(true);
        set_replacement_msg_ssl(scom);
        replacement_msg += "(ssl: enforced)";
    }
}

void MitmProxy::init_content_replace() {
    content_rule_ = std::make_unique<std::vector<ProfileContentRule>>();
}

std::optional<buffer> MitmProxy::content_replace_apply(const buffer &ref) {
    const std::string data = ref.str();
    std::string result = data;
    bool will_replace = false;

    int stage = 0;
    for(auto& profile: *content_rule()) {
        
        try {
            const std::regex re_match(profile.match.c_str());
            const std::string repl = profile.replace;
            
            if(profile.replacement_due()) {
                auto replacement = regex_replace_fill(result, profile.match, repl, profile.fill_length ? " " : nullptr);
                if(replacement.has_value()) {
                    will_replace = true;
                    result = replacement.value();
                }
                if (profile.replace_each_nth > 1)
                    _dia("Replacing bytes[stage %d]: n-th counter hit", stage);
            }

            _dia("Replacing bytes[stage %d]:",stage);
        }
        catch(std::regex_error const& e) {
        _not("MitmProxy::content_replace_apply: failed to replace string: %s", e.what());
        }
        
        ++stage;
    }

    if(will_replace) {
        buffer ret_b;
        ret_b.append(result.c_str(), result.size());

        _dia("content rewritten: original %d bytes with new %d bytes.", ref.size(), ret_b.size());
        _dum("Replacing bytes (%d):\n%s\n# with bytes(%d):\n%s", data.size(), hex_dump(ref).c_str(),
             ret_b.size(), hex_dump(ret_b).c_str());
        return ret_b;
    }
    return std::nullopt;
}


void MitmProxy::tap_left() {
    _dia("MitmProxy::tap left: start");

    auto lefties = { left_sockets, left_delayed_accepts, left_pc_cx, left_bind_sockets };

    for ( auto const& vec: lefties ) {
        for (auto* cx: vec) {
            com()->unset_monitor(cx->socket());
            cx->waiting_for_peercom(true);
            cx->io_disabled(true);
        }
    }
}

void MitmProxy::tap_right() {
    _dia("MitmProxy::tap right: start");

    auto righties = { right_sockets, right_delayed_accepts, right_pc_cx, right_bind_sockets };

    for ( auto const& vec: righties ) {
        for (auto cx: vec) {
            com()->unset_monitor(cx->socket());
            cx->waiting_for_peercom(true);
            cx->io_disabled(true);
        }
    }
}

void MitmProxy::tap() {
    tap_left();
    tap_right();
}

void MitmProxy::untap_left() {
    _dia("MitmProxy::untap left: start");

    auto lefties = { left_sockets, left_delayed_accepts, left_pc_cx, left_bind_sockets };

    for ( auto const& vec: lefties ) {
        for (auto *cx: vec) {

            com()->set_poll_handler(cx->socket(), this);
            com()->set_write_monitor(cx->socket());

            cx->waiting_for_peercom(false);
            cx->io_disabled(false);
        }
    }
}

void MitmProxy::untap_right() {

    _dia("MitmProxy::untap: start");

    auto righties = { right_sockets, right_delayed_accepts, right_pc_cx, right_bind_sockets };

    for ( auto const& vec: righties ) {
        for (auto cx: vec) {

            com()->set_poll_handler(cx->socket(), this);
            com()->set_write_monitor(cx->socket());

            cx->waiting_for_peercom(false);
            cx->io_disabled(false);
        }
    }
}


void MitmProxy::untap() {
    untap_left();
    untap_right();
}

MitmHostCX* MitmProxy::first_left() const {
    MitmHostCX* ret{};
    
    if(! left_sockets.empty()) {
        auto* l = left_sockets.at(0);
          ret = MitmHostCX::from_baseHostCX(l);
    }
    else if(! left_delayed_accepts.empty()) {
        auto* l = left_delayed_accepts.at(0);
        ret = MitmHostCX::from_baseHostCX(l);
    }
        
    return ret;
}

MitmHostCX* MitmProxy::first_right() const {
    MitmHostCX* ret = nullptr;
    
    if(! right_sockets.empty()) {
        auto* r = right_sockets.at(0);
        ret = MitmHostCX::from_baseHostCX(r);
    }
    else if(! right_delayed_accepts.empty()) {
        auto* r = right_delayed_accepts.at(0);
        ret = MitmHostCX::from_baseHostCX(r);
    }

    return ret;
}



bool MitmMasterProxy::detect_ssl_on_plain_socket(int sock) {
    constexpr unsigned int NEW_CX_PEEK_BUFFER_SZ = 10;
    constexpr auto retry_interval = std::chrono::microseconds(500);
    constexpr auto detection_timeout = std::chrono::microseconds(12500);

    if (sock < 0) return false;

    const auto deadline = std::chrono::steady_clock::now() + detection_timeout;
    while (true) {
        unsigned char peek_buffer[NEW_CX_PEEK_BUFFER_SZ]{};
        const auto bytes = ::recv(sock, peek_buffer, NEW_CX_PEEK_BUFFER_SZ,
                                  MSG_PEEK | MSG_DONTWAIT);

        // A TLS handshake record needs the five-byte record header and the
        // first handshake byte.  Do not let fragmentation around accept()
        // decide whether the same flow is inspected or passed as plaintext.
        if (bytes >= 6) {
            const bool handshake_record = peek_buffer[0] == 0x16 && peek_buffer[1] == 0x03;
            const bool hello = peek_buffer[5] == 0x00 || peek_buffer[5] == 0x01 ||
                               peek_buffer[5] == 0x02;
            if (handshake_record && hello) {
                _inf("detect_ssl_on_plain_socket: SSL detected on socket %d", sock);
                return true;
            }
            return false;
        }

        // recv()==0 is an orderly close.  Retrying it only stalls the accept
        // worker and cannot produce more bytes.
        if (bytes == 0 || !ssl_autodetect_harder ||
                std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return false;
        }

        std::this_thread::sleep_for(retry_interval);
        _dia("detect_ssl_on_plain_socket: SSL strict detection on socket %d: delayed by %lldusec",
             sock, static_cast<long long>(retry_interval.count()));
    }
}

baseHostCX* MitmMasterProxy::new_cx(int s) {
    
    _deb("MitmMasterProxy::new_cx: new_cx start");
    
    bool is_ssl = false;
    bool is_ssl_port = false;
    
    auto* my_sslcom = dynamic_cast<SSLCom*>(com());
    baseCom* c = nullptr;
    
    if(my_sslcom != nullptr) {
        is_ssl_port = true;
    }
    else if(ssl_autodetect) {
        // my com is NOT ssl-based, trigger auto-detect

        is_ssl = detect_ssl_on_plain_socket(s);
        if(! is_ssl) {
            c = com()->slave();
        } else {
            c = new baseSSLMitmCom<SSLCom>();
            c->master(com());
        } 
    }
    
    if(! c) {
        c = com()->slave();
    }
    
    auto r = new MitmHostCX(c,s);
    if (is_ssl) {
        _inf("Connection %s: SSL detected on unusual port.", r->c_type());
        r->is_ssl = true;
        r->is_ssl_port = is_ssl_port;
    }
    if(is_ssl_port) {
        r->is_ssl = true;
    }
    
    _deb("Pausing new connection %s", r->c_type());
    r->waiting_for_peercom(true);
    return r; 
}

void MitmMasterProxy::on_left_new(std::unique_ptr<baseHostCX> accepted_cx) {
    // ok, we just accepted socket, created context for it (using new_cx) and we probably need ... 
    // to create child proxy and attach this cx to it.

    if(not accepted_cx || not accepted_cx->com()) {
        _err("on_left_new: missing accepted connection or transport");
        return;
    }

    if(! accepted_cx->com()->nonlocal_dst_resolved()) {
        _err("on_left_new: cannot resolve socket destination");
        accepted_cx->shutdown();
        return;
    }

    std::string source_host;
    std::string source_port;

    if(not accepted_cx->com()->resolve_socket_src(accepted_cx->socket(), &source_host, &source_port)) {
        _err("on_left_new: cannot resolve socket source");

        accepted_cx->shutdown();
        return;
    }


    std::string target_host = accepted_cx->com()->nonlocal_dst_host();
    unsigned short target_port = accepted_cx->com()->nonlocal_dst_port();


    auto target_cx = std::make_unique<MitmHostCX>(accepted_cx->com()->slave(),
                                                  target_host.c_str(),
                                                  string_format("%d",target_port).c_str());

    auto new_proxy = sx::proxymaker::make(std::move(accepted_cx), std::move(target_cx));
    if(not new_proxy) {
        _err("on_left_new: cannot create child proxy");
        return;
    }
    auto lcx = logan_context(new_proxy->to_string(iNOT));

    if(not sx::proxymaker::policy(new_proxy, false)) {
        return;
    }

    if(not sx::proxymaker::setup_snat(new_proxy, source_host, source_port)) {
        return;
    }

    if(not sx::proxymaker::connect(this, std::move(new_proxy))) {
        return;
    }

    _deb("MitmMasterProxy::on_left_new: finished");
}

int MitmMasterProxy::handle_sockets_once(baseCom* c) {
    process_session_lists(*this);
    return ThreadedAcceptorProxy<MitmProxy>::handle_sockets_once(c);
}

int MitmUdpProxy::handle_sockets_once(baseCom* c) {
    process_session_lists(*this);
    return ThreadedReceiverProxy<MitmProxy>::handle_sockets_once(c);
}


void MitmUdpProxy::on_left_new(std::unique_ptr<baseHostCX> accepted_cx)
{
    if(not accepted_cx || not accepted_cx->com()) {
        _err("on_left_new: missing accepted datagram connection or transport");
        return;
    }

    std::string source_host;
    std::string source_port;

    // Resolve before proxymaker::make transfers the context into a child
    // proxy. Deleting it after that transfer leaves the unique_ptr with a
    // dangling left context and causes a second delete during unwind.
    if(not accepted_cx->com()->resolve_socket_src(
            accepted_cx->socket(), &source_host, &source_port)) {
        _err("on_left_new: cannot resolve socket source");
        accepted_cx->shutdown();
        return;
    }

    std::string target_host = accepted_cx->com()->nonlocal_dst_host();
    unsigned short target_port = accepted_cx->com()->nonlocal_dst_port();

    auto target_cx = std::make_unique<MitmHostCX>(accepted_cx->com()->slave(),
                                                  target_host.c_str(),
                                                  string_format("%d",target_port).c_str());

    auto new_proxy = sx::proxymaker::make(std::move(accepted_cx), std::move(target_cx));
    if(not new_proxy) {
        _err("on_left_new: cannot create child datagram proxy");
        return;
    }

    auto lcx = logan_context(new_proxy->to_string(iNOT));

    if(not sx::proxymaker::policy(new_proxy, false)) {
        return;
    }

    if(not sx::proxymaker::setup_snat(new_proxy, source_host, source_port)) {
        return;
    }

    if(not sx::proxymaker::connect(this, std::move(new_proxy))) {
        return;
    }

    _deb("MitmUDPProxy::on_left_new: finished");
}

baseHostCX* MitmUdpProxy::MitmUdpProxy::new_cx(int s) {
    return new MitmHostCX(com()->slave(),s);
}
