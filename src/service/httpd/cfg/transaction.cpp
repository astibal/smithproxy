#include "transaction.hpp"

#include <utility>

#ifndef SX_CFG_TRANSACTION_CODEC_ONLY
 #include <microhttpd.h>

 #include <service/cfgapi/cfg_tx_basket.hpp>
 #include <service/cfgapi/cfgapi.hpp>
 #include <service/httpd/handlers/handlers.hpp>
 #include <service/httpd/httpd.hpp>
#endif

namespace sx::webserver::cfg_tx_api {
namespace {

using nlohmann::json;
namespace tx = sx::cfg::tx;

tx::Issue issue(std::size_t index,
                std::string code,
                std::string path,
                std::string detail) {
    return tx::Issue {index, std::move(code), std::move(path), std::move(detail)};
}

template<class T>
tx::Result<T> required(json const& object,
                       char const* name,
                       std::size_t index,
                       std::string const& path) {
    auto value = object.find(name);
    if(value == object.end()) {
        return issue(index, "missing_field", path, std::string("Missing field: ") + name);
    }
    try {
        return value->get<T>();
    } catch(json::exception const&) {
        return issue(index, "invalid_field", path, std::string("Invalid field: ") + name);
    }
}

tx::Result<tx::Value> decode_value(json const& encoded,
                                   std::size_t index,
                                   std::string const& path) {
    // JSON alone cannot type an empty array and its numeric representation is
    // not identical to libconfig. The explicit type keeps the wire contract
    // deterministic before a value reaches Candidate validation.
    if(!encoded.is_object()) {
        return issue(index, "invalid_value", path, "Value must contain type and data");
    }
    auto type = required<std::string>(encoded, "type", index, path);
    if(!type) return type.error();
    auto data = encoded.find("data");
    if(data == encoded.end()) {
        return issue(index, "missing_field", path, "Missing field: data");
    }

    try {
        if(*type == "int") return tx::Value {data->get<std::int64_t>()};
        if(*type == "double") return tx::Value {data->get<double>()};
        if(*type == "bool") return tx::Value {data->get<bool>()};
        if(*type == "string") return tx::Value {data->get<std::string>()};
        if(*type == "int_array") return tx::Value {data->get<std::vector<std::int64_t>>()};
        if(*type == "double_array") return tx::Value {data->get<std::vector<double>>()};
        if(*type == "bool_array") return tx::Value {data->get<std::vector<bool>>()};
        if(*type == "string_array") return tx::Value {data->get<std::vector<std::string>>()};
    } catch(json::exception const&) {
        return issue(index, "invalid_value", path, "Value data does not match its declared type");
    }
    return issue(index, "unknown_value_type", path, "Unknown transaction value type: " + *type);
}

tx::Result<tx::Op> decode_operation(json const& encoded, std::size_t index) {
    if(!encoded.is_object()) {
        return issue(index, "invalid_operation", {}, "Operation must be an object");
    }
    auto kind = required<std::string>(encoded, "op", index, {});
    if(!kind) return kind.error();
    auto path = required<std::string>(encoded, "path", index, {});
    if(!path) return path.error();

    // Decode into the same operation model used by CLI transactions. HTTP is
    // only an adapter; mutation and validation remain in the cfgapi layer.
    if(*kind == "set") {
        auto value = encoded.find("value");
        if(value == encoded.end()) {
            return issue(index, "missing_field", *path, "Missing field: value");
        }
        auto decoded = decode_value(*value, index, *path);
        if(!decoded) return decoded.error();
        return tx::Op {tx::Set {std::move(*path), std::move(*decoded)}};
    }
    if(*kind == "add") {
        auto name = required<std::string>(encoded, "name", index, *path);
        if(!name) return name.error();
        return tx::Op {tx::Add {std::move(*path), std::move(*name)}};
    }
    if(*kind == "remove") {
        auto entries = required<std::vector<std::string>>(encoded, "entries", index, *path);
        if(!entries) return entries.error();
        return tx::Op {tx::Remove {std::move(*path), std::move(*entries)}};
    }
    if(*kind == "move") {
        auto source = required<std::size_t>(encoded, "source", index, *path);
        if(!source) return source.error();
        auto target = required<std::size_t>(encoded, "target", index, *path);
        if(!target) return target.error();
        auto position = required<std::string>(encoded, "position", index, *path);
        if(!position) return position.error();
        if(*position != "before" && *position != "after") {
            return issue(index, "invalid_position", *path, "Move position must be before or after");
        }
        return tx::Op {tx::Move {
            std::move(*path),
            *source,
            *position == "before" ? tx::Position::before : tx::Position::after,
            *target,
        }};
    }
    return issue(index, "unknown_operation", *path, "Unknown transaction operation: " + *kind);
}

}  // namespace

tx::Result<std::vector<tx::Op>> decode_operations(json const& value) {
    if(!value.is_array() || value.empty()) {
        return issue(
            tx::Issue::no_operation,
            "invalid_operations",
            {},
            "Operations must be a non-empty array");
    }

    // Preserve request order because later operations intentionally see the
    // candidate produced by every preceding operation.
    std::vector<tx::Op> operations;
    operations.reserve(value.size());
    for(std::size_t index = 0; index < value.size(); ++index) {
        auto operation = decode_operation(value[index], index);
        if(!operation) return operation.error();
        operations.push_back(std::move(*operation));
    }
    return operations;
}

}  // namespace sx::webserver::cfg_tx_api

#ifndef SX_CFG_TRANSACTION_CODEC_ONLY
namespace sx::webserver {
namespace {

namespace tx = sx::cfg::tx;

tx::TxBasket& tx_basket() {
    // One process-wide basket matches the one process-wide commit lease.
    // Its internal mutex also makes requests from different HTTP workers safe.
    static tx::TxBasket basket;
    return basket;
}

Http_JsonResponseParams response(nlohmann::json body, unsigned int status = MHD_HTTP_OK) {
    Http_JsonResponseParams result;
    result.response_code = status;
    result.response = std::move(body);
    return result;
}

unsigned int issue_status(tx::Issue const& issue) {
    // Keep machine-readable cfgapi error codes in the body and use HTTP status
    // only for their broad class. Clients should branch on issue.code.
    if(issue.code == "unknown_transaction") return MHD_HTTP_NOT_FOUND;
    if(issue.code == "lease_busy" || issue.code == "stale_revision" ||
       issue.code == "lease_expired" || issue.code == "not_prepared") {
        return MHD_HTTP_CONFLICT;
    }
    if(issue.code == "apply_unavailable" || issue.code == "runtime_apply_failed" ||
       issue.code == "hash_failed") {
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }
    return MHD_HTTP_UNPROCESSABLE_ENTITY;
}

Http_JsonResponseParams error_response(tx::Issue const& issue) {
    nlohmann::json error {
        {"code", issue.code},
        {"detail", issue.detail},
    };
    if(issue.operation != tx::Issue::no_operation) error["operation"] = issue.operation;
    if(!issue.path.empty()) error["path"] = issue.path;
    return response({{"state", "error"}, {"error", std::move(error)}}, issue_status(issue));
}

tx::Result<nlohmann::json> request_params(std::string const& request) {
    // Authentication fields live beside params in the existing API envelope.
    // Transaction handlers deliberately inspect only the params object.
    try {
        auto body = nlohmann::json::parse(request);
        auto params = body.find("params");
        if(params == body.end() || !params->is_object()) {
            return tx::Issue {
                tx::Issue::no_operation,
                "invalid_request",
                {},
                "Request requires a params object",
            };
        }
        return *params;
    } catch(nlohmann::json::exception const&) {
        return tx::Issue {
            tx::Issue::no_operation,
            "invalid_json",
            {},
            "Request body is not valid JSON",
        };
    }
}

tx::Result<std::string> transaction_token(nlohmann::json const& params) {
    auto value = params.find("transaction");
    if(value == params.end() || !value->is_string() || value->get_ref<std::string const&>().empty()) {
        return tx::Issue {
            tx::Issue::no_operation,
            "missing_transaction",
            {},
            "Request requires a transaction token",
        };
    }
    return value->get<std::string>();
}

}  // namespace

Http_JsonResponseParams cfg_transaction_begin(
    MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    auto params = request_params(request);
    if(!params) return error_response(params.error());

    // Owner is diagnostic bookkeeping, not authorization. The surrounding
    // token_protected responder has already authenticated this request.
    const std::string owner = "api:" + authorized::client_address(connection);
    tx::Transaction::CreateResult transaction = [&] {
        auto base = params->find("base_revision");
        if(base == params->end()) return CfgFactory::make_transaction(owner);
        if(!base->is_string() || base->get_ref<std::string const&>().empty()) {
            return tx::Transaction::CreateResult {tx::Issue {
                tx::Issue::no_operation,
                "invalid_base_revision",
                {},
                "base_revision must be a non-empty string",
            }};
        }
        return CfgFactory::make_transaction(owner, base->get<std::string>());
    }();

    // From this point the basket, rather than the request stack, owns both the
    // Transaction and its lease until commit, abort, or timeout.
    auto opened = tx_basket().begin(std::move(transaction));
    if(!opened) return error_response(opened.error());
    return response({
        {"state", "open"},
        {"transaction", opened->token},
        {"base_revision", opened->base_revision},
        {"expires_in_ms", opened->expires_in.count()},
    });
}

Http_JsonResponseParams cfg_transaction_prepare(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    auto params = request_params(request);
    if(!params) return error_response(params.error());
    auto token = transaction_token(*params);
    if(!token) return error_response(token.error());

    auto encoded = params->find("operations");
    if(encoded == params->end()) {
        return error_response(tx::Issue {
            tx::Issue::no_operation,
            "missing_operations",
            {},
            "Request requires operations",
        });
    }
    auto operations = cfg_tx_api::decode_operations(*encoded);
    if(!operations) return error_response(operations.error());

    // prepare builds the complete candidate, but the response intentionally
    // exposes only verification metadata. Snapshot bytes stay in TxBasket.
    auto prepared = tx_basket().prepare(*token, std::move(*operations));
    if(!prepared) return error_response(prepared.error());
    return response({
        {"state", "prepared"},
        {"content_hash", prepared->content_hash},
        {"operation_count", prepared->operation_count},
        {"expires_in_ms", prepared->expires_in.count()},
    });
}

Http_JsonResponseParams cfg_transaction_commit(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    auto params = request_params(request);
    if(!params) return error_response(params.error());
    auto token = transaction_token(*params);
    if(!token) return error_response(token.error());

    std::string description;
    if(auto value = params->find("description"); value != params->end()) {
        if(!value->is_string()) {
            return error_response(tx::Issue {
                tx::Issue::no_operation,
                "invalid_description",
                {},
                "description must be a string",
            });
        }
        description = value->get<std::string>();
    }

    // TxBasket supplies the previously prepared snapshot. Transaction::commit
    // rechecks lease, base revision, and content hash before runtime apply.
    auto committed = tx_basket().commit(*token, std::move(description));
    if(!committed) return error_response(committed.error());
    return response({
        {"state", "committed"},
        {"revision", committed->revision},
        {"content_hash", committed->content_hash},
        {"unsaved", CfgFactory::board()->unsaved()},
    });
}

Http_JsonResponseParams cfg_transaction_abort(
    [[maybe_unused]] MHD_Connection* connection,
    [[maybe_unused]] std::string const& method,
    std::string const& request) {
    auto params = request_params(request);
    if(!params) return error_response(params.error());
    auto token = transaction_token(*params);
    if(!token) return error_response(token.error());

    // Abort carries no snapshot back to the caller; destroying the basket
    // entry is enough to discard the candidate and release its lease.
    auto aborted = tx_basket().abort(*token);
    if(!aborted) return error_response(aborted.error());
    return response({{"state", "aborted"}});
}

}  // namespace sx::webserver
#endif
