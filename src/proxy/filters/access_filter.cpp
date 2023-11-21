
#include <proxy/filters/access_filter.hpp>
#include <service/http/webhooks.hpp>

void AccessFilter::update(socle::side_t side, buffer const& buf) {

    // update entropy statistics
    if(side == side_t::LEFT and not already_applied) {
        _deb("AccessFilter[%c]: requesting webhook while received first %d bytes", socle::from_side(side), buf.size());

        nlohmann::json pay = { { "session", connection_label },
                               { "policy", parent()->matched_policy() },
                               { "require", "origin-info" } };


        auto process_reply = [&](auto code, auto response_data) {
            if(code >= 200 and code < 300) {
                auto json_obj = nlohmann::json::parse(response_data, nullptr, false);
                if(json_obj.is_discarded()) {
                    _err("AccessFilter: received data are not JSON");
                    return;
                }

                access_response = json_obj;
                bool has_response = json_obj.contains("access-response");

                if(has_response and json_obj["access-response"] == "accept") {
                    _dia("AccessFilter: received 'accept' response");
                    access_allowed = true;
                }
                else if(has_response and json_obj["access-response"] == "reject") {
                    _dia("AccessFilter: received 'reject' response");
                    parent()->state().dead(true);
                }
                else {
                    _dia("AccessFilter: received unsupported response");
                }
            }
            else {
                _err("AccessFilter: fail-open - requiring 2xx code and json response with result");
            }
        };


        sx::http::webhooks::send_action_wait("access-request", connection_label, pay,
            [&](sx::http::AsyncRequest::expected_reply const& reply){

            if(reply.has_value()) {
                _dia("AccessFilter: received response");

                auto code = reply.value().first;
                auto response_data = reply.value().second;

                process_reply(code, response_data);
            }
            else {
                _dia("AccessFilter: response NOT received");
            }
        });

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


