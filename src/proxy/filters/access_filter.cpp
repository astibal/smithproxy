
#include <proxy/filters/access_filter.hpp>
#include <proxy/filters/access_filter_decision.hpp>
#include <service/http/webhooks.hpp>

void AccessFilter::init() {

    state = state_t::INIT;

    // run update right when the filter is created (likely when connection is being opened)
    if(not already_applied) {
        buffer b;
        _deb("AccessFilter[%c]: requesting webhook on init");
        update(side_t::LEFT, b);
    }

    state = state_t::DATA;
}

void AccessFilter::update(socle::side_t side, buffer const& buf) {

    auto str_state = state_str[state];

    auto lc_ = std::scoped_lock(update_lock);

    // update entropy statistics
    if(not already_applied) {
        if (!parent()) {
            _err("AccessFilter: missing parent proxy");
            already_applied = true;
            return;
        }

        _deb("AccessFilter[%c]: access-request webhook on first %d bytes", socle::from_side(side), buf.size());

        nlohmann::json pay = { { "session", connection_label },
                               { "policy", parent()->matched_policy() },
                               { "require", "origin-info" },
                               { "bytes_side", string_format("%c",socle::from_side(side)) },
                               { "bytes_size", buf.size() },
                               { "state", str_state }
                            };

        auto process_reply = [&](auto code, auto const& response_data) {
            auto result = sx::proxy::parse_access_response(code, response_data, fail_open_);
            if (!result.response.is_discarded() && !result.response.is_null()) {
                access_response = std::move(result.response);
            }

            switch (result.decision) {
                case sx::proxy::access_decision::accept:
                    _dia("AccessFilter: received 'accept' response");
                    access_allowed = true;
                    break;
                case sx::proxy::access_decision::reject:
                    _dia("AccessFilter: received 'reject' response");
                    parent()->state().dead(true);
                    break;
                case sx::proxy::access_decision::fail_open_invalid_response:
                    _dia("AccessFilter: received unsupported response");
                    break;
                case sx::proxy::access_decision::fail_open_transport:
                    _err("AccessFilter: fail-open - requiring 2xx code and json response with result");
                    break;
                case sx::proxy::access_decision::fail_closed_invalid_response:
                    _err("AccessFilter: invalid response, rejecting (fail-closed)");
                    parent()->state().dead(true);
                    break;
                case sx::proxy::access_decision::fail_closed_transport:
                    _err("AccessFilter: webhook failure, rejecting (fail-closed)");
                    parent()->state().dead(true);
                    break;
            }
        };


        auto const dispatched = sx::http::webhooks::send_action_wait("access-request", connection_label, pay,
            [&](sx::http::AsyncRequest::expected_reply const& reply){

            if(reply.has_value()) {
                _dia("AccessFilter: received response");

                auto code = reply.value().response.first;
                auto response_data = reply.value().response.second;

                process_reply(code, response_data);
            }
            else {
                _dia("AccessFilter: response NOT received");
                if(not fail_open_) {
                    _err("AccessFilter: webhook transport failed, rejecting (fail-closed)");
                    parent()->state().dead(true);
                }
            }
        });

        if(not dispatched and not fail_open_) {
            _err("AccessFilter: webhook unavailable, rejecting (fail-closed)");
            parent()->state().dead(true);
        }

        // we are already called, so this won't trigger additional queries
        already_applied = true;
    }
}

void AccessFilter::proxy(baseHostCX *from, baseHostCX *to, socle::side_t side, bool redirected) {
    update(side, from->to_read());
}


bool AccessFilter::update_states() {
    return true;
}

std::string AccessFilter::to_string(int verbosity) const {
    std::stringstream ss;
    ss << "\r\n === Access-Filter: ===";

    ss << "\r\n " << connection_label;
    ss << "\r\n " << nlohmann::to_string(access_response);

    ss << "\r\n === Access-Filter: ===";
    return ss.str();
}

nlohmann::json AccessFilter::to_json(int verbosity) const {

    auto json_all = nlohmann::json();
    json_all["info"] = { {"session", connection_label}, { "access-response", access_response } };

    return json_all;
}

AccessFilter::~AccessFilter() {
    // there used to be useful code here
}
