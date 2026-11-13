#include <service/core/session_interfaces.hpp>
#include <optional>
#include <thread>
#include <mutex>

#include <nlohmann/json.hpp>

#include <log/logan.hpp>

#include <service/core/smithproxy.hpp>
#include <service/core/smithproxy_objapi.hpp>
#include <service/core/smithproxy_objapi_utils.hpp>
#include <service/core/sessionlist.hpp>
#include <service/quic/quicservice.hpp>
#include <service/http/jsonize.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/nbrhood.hpp>
#include <staticcontent.hpp>

void ObjAPI::for_each_proxy(std::function<void(MitmProxy*)> callable) {
    if (!callable) return;
    auto const& instance = SmithProxy::instance();

    auto list_worker = [callable](const char* title, auto& listener) {
        for (auto const& acc: listener) {
            for(auto const& wrk: acc->tasks()) {

                auto lc_ = std::scoped_lock(wrk.second->proxy_lock());

                for(auto const& p : wrk.second->proxies()) {
                    if(auto* proxy = dynamic_cast<MitmProxy*>(p.get()); proxy != nullptr) {
                        callable(proxy);
                    }
                }
            }
        }
    };

    list_worker("plain acceptor", instance.plain_proxies);
    list_worker("tls acceptor", instance.ssl_proxies);

    list_worker("udp receiver", instance.udp_proxies);
    list_worker("dtls receiver", instance.dtls_proxies);

    list_worker("socks acceptor", instance.socks_proxies);

    list_worker("plain redirect acceptor", instance.redir_plain_proxies);
    list_worker("dns redirect receiver", instance.redir_udp_proxies);
    list_worker("tls redirect acceptor", instance.redir_ssl_proxies);
}


std::string ObjAPI::instance_OID() {
    return string_format("Proxy-%lX", StaticContent::boot_random);
}

nlohmann::json ObjAPI::proxy_session_connid_list() {

    using nlohmann::json;
    json ret = json::array();

    for_each_proxy([&ret](MitmProxy const* px){
        if(px and px->first_left() and px->first_right()) ret.push_back(px->to_connection_ID());
    });

    return ret;
}

nlohmann::json ObjAPI::proxy_session_connid_list_plus() {

    using nlohmann::json;
    json ret = json::array();

    for_each_proxy([&ret](MitmProxy const* px){
        if(px and px->first_left() and px->first_right())
            ret.push_back(string_format("%s=%s", px->to_connection_ID().c_str(), px->to_connection_label().c_str()));
    });

    return ret;
}


nlohmann::json ObjAPI::proxy_session_list_json(bool active_only, bool tls_info, bool verbose) {
    using nlohmann::json;

    auto verbosity = verbose ? iDIA : iINF;

    auto json_single_proxy = [active_only, tls_info, verbosity](MitmProxy* proxy) -> std::optional<nlohmann::json> {
        if(active_only) {
            if(proxy->stats().mtr_up.get() == 0L and proxy->stats().mtr_down.get() == 0L)
                return std::nullopt;
        }

        if(proxy->lsize() == 0 or proxy->rsize() == 0) {
            return std::nullopt;
        }

        auto proxy_detail = jsonize::from(proxy, verbosity);
        const auto* left = proxy->first_left();
        const auto* right = proxy->first_right();
        proxy_detail["interfaces"] = sx::net::session_interfaces_json(
            left && left->com() ? left->com()->ingress_ifindex() : 0,
            right && right->com() ? right->com()->egress_ifindex() : 0);

        if(tls_info) {
            nlohmann::json left;
            nlohmann::json right;

            if(proxy->first_left()) {
                left = jsonize::from(proxy->first_left()->com(), verbosity);
            }
            if(proxy->first_right()) {
                right = jsonize::from(proxy->first_right()->com(), verbosity);
            }

            proxy_detail["tlsinfo"] = { { "left", left },
                                        { "right", right }
            };
        }
        return proxy_detail;
    };



    auto request = SessionList::json(session_list_worker_count(),
        [json_single_proxy](MitmProxy* proxy) -> std::optional<nlohmann::json> {
            return json_single_proxy(proxy);
        });

    dispatch_session_list(request);

    // QUIC children live on separate workers. Reuse their owner-thread snapshot
    // queue: the renderer runs under child locks, never on this API thread.
    // The queue transports strings for CLI as well, so encode each JSON record
    // there and decode only the completed, immutable snapshot here.
    std::vector<std::future<sx::quic::listener_service::session_details>> quic_requests;
    std::vector<std::map<std::uint64_t, nlohmann::json>> quic_tls;
    for (auto const& service : SmithProxy::instance().quic_services) {
        auto& parent_tls = quic_tls.emplace_back();
        if (tls_info) {
            // Reuse the value-only parent snapshot already consumed by CLI.
            // IDs are listener-local, so keep each listener's lookup separate.
            auto tls_json = [](sx::quic::tls_snapshot const& tls, std::string const& alpn) {
                nlohmann::json value = {
                    {"available", tls.available}, {"established", tls.established},
                    {"ended", tls.ended}, {"handshake", tls.handshake_status()}, {"alpn", alpn}
                };
                if (tls.available) {
                    value.update({{"version", tls.version}, {"cipher", tls.cipher},
                        {"sni", tls.server_name}, {"state", tls.state},
                        {"resumed", tls.resumed}, {"has_ticket", tls.has_ticket},
                        {"verify_peer", tls.verify_peer}, {"verify_result", tls.verify_result},
                        {"verify_error", tls.verify_error}});
                    if (tls.has_ticket) value["ticket"]["lifetime_hint"] = tls.ticket_lifetime_hint;
                }
                return value;
            };
            for (auto const& session : service->session_diagnostics()) {
                parent_tls[session.id] = {
                    {"source", "quic parent"},
                    {"left", tls_json(session.downstream_tls, session.downstream_alpn)},
                    {"right", tls_json(session.upstream_tls, session.upstream_alpn)}
                };
            }
        }
        quic_requests.push_back(service->request_session_details(
            [json_single_proxy](MitmProxy* proxy) -> std::optional<std::string> {
                auto detail = json_single_proxy(proxy);
                if (!detail) return std::nullopt;
                (*detail)["origin"] = "quic worker";
                if (proxy->webhook_stream) {
                    (*detail)["parent_id"] = proxy->webhook_stream->parent_id;
                    (*detail)["stream_id"] = proxy->webhook_stream->stream_id;
                }
                return detail->dump();
            }));
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (!request->wait_for(std::chrono::seconds(5))) return nlohmann::json::array();
    auto result = request->json_result();
    try {
        for (std::size_t listener = 0; listener < quic_requests.size(); ++listener) {
            auto& pending = quic_requests[listener];
            if (pending.wait_until(deadline) != std::future_status::ready)
                return nlohmann::json::array();
            for (auto const& [id, streams] : pending.get()) {
                for (auto const& stream : streams) {
                    auto detail = nlohmann::json::parse(stream);
                    if (tls_info) {
                        auto const parent = quic_tls[listener].find(id);
                        // Parent and child snapshots are asynchronous. Do not
                        // present empty SSLCom data as the child's QUIC TLS.
                        detail["tlsinfo"] = parent != quic_tls[listener].end()
                            ? parent->second : nlohmann::json{{"source", "quic parent"}, {"available", false}};
                    }
                    result.push_back(std::move(detail));
                }
            }
        }
    } catch (std::exception const& error) {
        Log::get()->events().insert(ERR, "QUIC API session snapshot failed: %s", error.what());
        return nlohmann::json::array();
    }
    return result;
}


nlohmann::json ObjAPI::neighbor_update(std::string const& request) {
    using namespace jsonize;

    // get a vector of string pairs - pair represents hostname and its tag string
    using host_tags_vector = std::vector<std::pair<std::string, std::string>>;
    auto values = load_json_params<host_tags_vector>(request, "hostname_tags");

    std::size_t updated {0};

    if(values.has_value()) {
        auto& nbrs = NbrHood::instance().cache();
        auto lc_ = std::scoped_lock(nbrs.lock());

        for (auto const &[ hostname, update_string ] : values.value()) {
            auto nbr = nbrs.get_ul(hostname);
            if(nbr) {
                nbr.value()->tags_update(update_string);
                updated++;
            }
        }
    }

    return {
            { "updated_entries", updated},
    };
}

nlohmann::json ObjAPI::neighbor_list(bool flag_raw, unsigned int last_n_days) {
    if(not flag_raw) {
        return NbrHood::instance().to_json([&](auto const &nbr) {
            if (not nbr.timetable.empty()) {
                auto now_de = epoch_days(time(nullptr));
                if (sx::objapi::day_is_within_age(
                        now_de, nbr.timetable[0].days_epoch, last_n_days))
                    return true;
            }
            return false;
        });
    }
    else {
        return NbrHood::instance().ser_json_out();
    }
}
