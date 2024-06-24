#include <nlohmann/json.hpp>

#include <service/core/smithproxy.hpp>
#include <proxy/nbrhood.hpp>


#include <service/http/webhooks.hpp>
#include <service/http/async_request.hpp>
#include <service/http/jsonize.hpp>

#include <unordered_map>


namespace sx::http::webhooks {


    static std::unordered_map<std::string, url_stats> _url_stats;
    static std::mutex _url_stats_lock;

    std::mutex& url_stats_lock() { return  _url_stats_lock; }
    std::unordered_map<std::string, url_stats>& url_stats_map() { return _url_stats; }

    static std::atomic_bool enabled = false;
    static std::string hostid;

    void set_enabled(bool val) {
        enabled = val;
    }
    bool is_enabled() {
        return enabled;
    }
    void set_hostid(std::string const& ref) {
        hostid = ref;
    }

    std::string const& get_hostid() {
        return hostid.empty() ? SmithProxy::instance().hostname : hostid;
    }

    struct default_callback {
        default_callback() = default;
        virtual ~default_callback() = default;

        void operator() (sx::http::expected_reply rep) const {

            if(rep.has_value()) {

                auto code = rep.value().response.first;
                if(code > 0) {
                    auto const& url = rep.value().request;
                    auto lc_ = std::scoped_lock(url_stats_lock());
                    auto& entry = url_stats_map()[url];
                    entry.url = url;

                    bool is_error = false;
                    if(code >= 400) {
                        is_error = true;
                    }

                    entry.update_incr(is_error);
                    on_reply(rep);
                }
                else {
                    // this is an initialization hook call!
                    on_init(rep);
                }
            }
        }

        virtual void on_reply([[maybe_unused]] sx::http::expected_reply const& rep) const {
            // this cannot be abstract class, it's used with a no-op response
        };
        virtual void on_init([[maybe_unused]] sx::http::expected_reply const& rep) const {
            // this cannot be abstract class, it's used with a no-op response
        };
    };

    void ping() {
        if(enabled) {
            nlohmann::json const ping = {
                                          { "action", "ping" },
                                          {"source", get_hostid() },
                                          {"type", "proxy"},
                                          {"instance", SmithProxy::instance().API.instance_OID() },
                                          {"proxies", SmithProxy::instance().API.proxy_session_connid_list() }
                                        };
            sx::http::AsyncRequest::emit(
                    to_string(ping),
                    default_callback());
        }
    }

    void ping_plus() {
        if(enabled) {
            nlohmann::json const ping = {
                { "action", "ping" },
                {"source", get_hostid() },
                {"type", "proxy"},
                {"instance", SmithProxy::instance().API.instance_OID() },
                {"proxies", SmithProxy::instance().API.proxy_session_connid_list() },
                {"proxies-plus", SmithProxy::instance().API.proxy_session_connid_list_plus() }
            };
            sx::http::AsyncRequest::emit(
                    to_string(ping),
                    default_callback());
        }
    }

    struct neighbor_reply : public default_callback {
        void on_init(sx::http::expected_reply const& rep) const override {
            if(rep.has_value()) {
                auto* ctrl = rep->ctrl;
                if(ctrl) {
                    ctrl->set_timeout(60);
                    ctrl->set_stale_detection(120); // allow some room to fetch data
                }
            }
        }

        void on_reply(sx::http::expected_reply const& rep) const override {
            auto const& body = rep->response.second;
            if(not body.empty()) {
                SmithProxy::api().neighbor_update(body);
            }
        }
    };

    void ping_neighbors() {
        if(enabled) {
            std::vector<std::string> hostnames;

            NbrHood::instance().for_each([&hostnames](auto const& n) {
               if(not n.hostname.empty()) hostnames.push_back(n.hostname);
            });

            nlohmann::json const nbr_ping = {
                    { "action", "neighbor" },
                    { "state", "ping" },
                    {"source", get_hostid() },
                    {"type", "proxy"},
                    { "addresses", hostnames }
            };
            sx::http::AsyncRequest::emit(
                    to_string(nbr_ping),
                    neighbor_reply());
        }
    }


    void neighbor_state(std::string const& address_str, std::string const& state) {
        const std::vector<std::string> vec = {address_str,};
        neighbor_state(vec, state);
    }

    void neighbor_state(std::vector<std::string> const& address_vec, std::string const& state) {
        if(enabled) {
            nlohmann::json nbr_update = {
                    { "action", "neighbor" },
                    { "state",  state },
                    {"source",  get_hostid() },
                    {"type",    "proxy"},
                    {"addresses", address_vec }
            };

            sx::http::AsyncRequest::emit(
                    to_string(nbr_update),
                    neighbor_reply());
        }
    }

    void send_action(std::string const& action, std::string const& action_id, nlohmann::json const& details) {
        if(enabled) {


            std::string msg_str;
            try {
                nlohmann::json msg = {
                        {"action", action},
                        {"id", action_id},
                        {"source", get_hostid() },
                        {"type",   "proxy"}};

                msg.push_back({"details", details});
                msg_str = to_string(msg);
            }
            catch(std::bad_array_new_length const& e) {
                Log::get()->events().insert(ERR, "webhook::send_action failed (bad_array_new_length): action=%s, id=%s: %s", action.c_str(),
                                            action_id.c_str(),
                                            e.what());
            }
            catch(std::exception const& e) {
                Log::get()->events().insert(ERR, "webhook::send_action failed(generic exception): action=%s, id=%s: %s", action.c_str(),
                                            action_id.c_str(),
                                            e.what());
            }
            catch(...) {
                Log::get()->events().insert(ERR, "webhook::send_action failed(unknown exception): action=%s, id=%s", action.c_str(),
                                            action_id.c_str());
            }

            if(not msg_str.empty()) {

                struct action_hook : public default_callback {
                    void on_reply([[maybe_unused]] sx::http::expected_reply const &rep) const override {
                        if(rep.has_value() and rep.value().response.first == 202) {
                            ping_plus();
                            ping_neighbors();
                        }
                    }
                };
                sx::http::AsyncRequest::emit(msg_str, action_hook());

            }
        }
    }

    // send action and wait - use hook,
    void send_action_wait(std::string const& action, std::string const& action_id, nlohmann::json const& details,
                          sx::http::AsyncRequest::reply_hook hook) {
        if(enabled) {
            nlohmann::json msg = {
                    {"action", action},
                    {"id", action_id},
                    {"source", get_hostid() },
                    {"type",   "proxy"}};

            msg.push_back({"details", details});
            sx::http::AsyncRequest::emit_wait(
                    to_string(msg),
                    hook);
        }
    }
}
