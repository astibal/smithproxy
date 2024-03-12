#include <optional>
#include <thread>
#include <mutex>

#include <nlohmann/json.hpp>

#include <socle/sobject.hpp>
#include <log/logan.hpp>

#include <service/core/smithproxy.hpp>
#include <service/core/smithproxy_objapi.hpp>
#include <service/http/jsonize.hpp>
#include <proxy/mitmproxy.hpp>
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


nlohmann::json ObjAPI::proxy_session_list_json(uint64_t oid, bool active_only, bool tls_info, bool verbose) {
    using nlohmann::json;
    auto const& instance = SmithProxy::instance();

    json ret;

    auto verbosity = verbose ? iDIA : iINF;

    auto json_single_proxy = [&](MitmProxy* proxy) -> std::optional<nlohmann::json> {
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



    if(oid != 0ULL) {
        auto lc_ = std::scoped_lock(socle::sobjectDB::getlock());

        auto it = socle::sobjectDB::oid_db().find(oid);
        if(it != socle::sobjectDB::oid_db().end()) {

            std::string what = it->second->c_type();
            if (what == "MitmProxy" || what == "SocksProxy") {
                auto *proxy = dynamic_cast<MitmProxy *>(it->second.get());
                if (proxy) {
                    auto single_ret = json_single_proxy(proxy);
                    if (single_ret.has_value()) ret.push_back(single_ret.value());
                    return ret;
                }
            }
        }
        return nlohmann::json::array();
    } else {

        auto list_worker = [&json_single_proxy, &ret](const char* title, auto& listener) {
            for (auto const& acc: listener) {
                for(auto const& wrk: acc->tasks()) {

                    auto lc_ = std::scoped_lock(wrk.second->proxy_lock());

                    for(auto const& [ p, _ ] : wrk.second->proxies()) {
                        if(auto* proxy = dynamic_cast<MitmProxy*>(p.get()); p != nullptr) {
                            auto single_ret = json_single_proxy(proxy);
                            if (single_ret.has_value()) {
                                single_ret.value()["origin"] = title;
                                ret.push_back(single_ret.value());
                            }
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

        if (ret.empty()) return nlohmann::json::array();

        return ret;
    }
}
