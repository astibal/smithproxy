#include <optional>
#include <thread>
#include <mutex>

#include <nlohmann/json.hpp>

#include <log/logan.hpp>

#include <service/core/smithproxy.hpp>
#include <service/core/smithproxy_objapi.hpp>
#include <service/core/sessionlist.hpp>
#include <service/http/jsonize.hpp>
#include <proxy/mitmproxy.hpp>
#include <proxy/nbrhood.hpp>
#include <staticcontent.hpp>

void ObjAPI::for_each_proxy(std::function<void(MitmProxy*)> callable) {
    auto const& instance = SmithProxy::instance();

    auto list_worker = [callable](const char* title, auto& listener) {
        for (auto const& acc: listener) {
            for(auto const& wrk: acc->tasks()) {

                auto lc_ = std::scoped_lock(wrk.second->proxy_lock());

                for(auto const& [ p, _ ] : wrk.second->proxies()) {
                    if(auto* proxy = dynamic_cast<MitmProxy*>(p.get()); p != nullptr) {
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
    json ret;

    for_each_proxy([&ret](MitmProxy const* px){
        if(px and px->first_left() and px->first_right()) ret.push_back(px->to_connection_ID());
    });

    return ret;
}

nlohmann::json ObjAPI::proxy_session_connid_list_plus() {

    using nlohmann::json;
    json ret;

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
    if (!request->wait_for(std::chrono::seconds(5))) return nlohmann::json::array();
    return request->json_result();
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
                auto delta = now_de - nbr.timetable[0].days_epoch;
                if (delta <= last_n_days)
                    return true;
            }
            return false;
        });
    }
    else {
        return NbrHood::instance().ser_json_out();
    }
}
