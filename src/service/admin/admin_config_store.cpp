#include "admin_config_store.hpp"

#include <service/cfgapi/cfg_archive.hpp>
#include <utils/crypto.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::string_view admin_config_path = "admin.cfg";

std::string detail_for(sx::admin::ChangeStatus status) {
    using Status = sx::admin::ChangeStatus;
    switch(status) {
        case Status::written:
            return {};
        case Status::invalid_name:
            return "administrator name is invalid";
        case Status::invalid_password:
            return "administrator password is invalid";
        case Status::already_exists:
            return "administrator already exists";
        case Status::not_found:
            return "administrator does not exist";
        case Status::last_enabled_administrator:
            return "the final enabled administrator cannot be disabled or removed";
        case Status::persistence_error:
            return "administrator configuration was not written";
    }
    return "administrator configuration was not written";
}

} // namespace

namespace sx::admin {

ConfigStore::ConfigStore(Context context): context_(context) {}

// Read the active archive under the same mutex used by configuration writers.
Admins ConfigStore::read() const {
    const auto guard = std::scoped_lock(context_.config_mutex);
    if(!context_.archive.available())
        throw std::runtime_error("native configuration archive is unavailable");

    const auto archive = sx::cfg::CfgArchive::read_archive(
        sx::cfg::smithproxy_schema(), "active.cftar", context_.archive.current());
    if(!archive.archive().contains(admin_config_path)) {
        return {};
    }

    return Admins::parse(archive.archive().at(admin_config_path).data);
}

AuthenticationStatus ConfigStore::authenticate(
    std::string_view name, std::string_view password) const {
    return read().authenticate(name, password);
}

ChangeResult ConfigStore::create(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string name,
    std::string_view password) {
    if(!valid_name(name)) {
        return {
            ChangeStatus::invalid_name,
            {},
            detail_for(ChangeStatus::invalid_name),
        };
    }

    auto verifier = sx::crypto::password_verifier(password);
    if(!verifier) {
        return {
            ChangeStatus::invalid_password,
            {},
            detail_for(ChangeStatus::invalid_password),
        };
    }

    return apply_change(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::move(name), verifier = std::move(*verifier)](Admins& admins) mutable {
            return add_administrator(
                admins, std::move(name), std::move(verifier));
        });
}

ChangeResult ConfigStore::change_password(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name,
    std::string_view password) {
    if(!valid_name(name)) {
        return {
            ChangeStatus::invalid_name,
            {},
            detail_for(ChangeStatus::invalid_name),
        };
    }

    auto verifier = sx::crypto::password_verifier(password);
    if(!verifier) {
        return {
            ChangeStatus::invalid_password,
            {},
            detail_for(ChangeStatus::invalid_password),
        };
    }

    return apply_change(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name), verifier = std::move(*verifier)](Admins& admins) mutable {
            return replace_password(
                admins, std::move(name), std::move(verifier));
        });
}

ChangeResult ConfigStore::set_enabled(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name,
    bool enabled) {
    if(!valid_name(name)) {
        return {
            ChangeStatus::invalid_name,
            {},
            detail_for(ChangeStatus::invalid_name),
        };
    }

    return apply_change(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name), enabled](Admins& admins) {
            return update_enabled(admins, name, enabled);
        });
}

ChangeResult ConfigStore::remove(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name) {
    if(!valid_name(name)) {
        return {
            ChangeStatus::invalid_name,
            {},
            detail_for(ChangeStatus::invalid_name),
        };
    }

    return apply_change(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name)](Admins& admins) {
            return erase_administrator(admins, name);
        });
}

ChangeResult ConfigStore::apply_change(
    std::string expected_revision,
    std::string expected_archive_hash,
    Change change) {
    const auto previous_archive_hash = expected_archive_hash;
    ChangeStatus change_status = ChangeStatus::persistence_error;
    // CfgResourceWriter owns revision checks, the cross-writer gate and atomic
    // archive publication. This layer supplies only the typed transformation.
    sx::cfg::CfgResourceWriter writer({
        context_.board, context_.gate, context_.config_mutex, context_.archive,
    });
    auto persistence = writer.transform(
        std::move(expected_revision), std::move(expected_archive_hash),
        std::string(admin_config_path),
        [&change, &change_status](const std::optional<std::string>& content) {
            return apply_to_content(
                content, change, change_status);
        },
        false,
        sx::cfg::ResourceActivation::immediate);

    if(!persistence.ok() && change_status == ChangeStatus::written) {
        change_status = ChangeStatus::persistence_error;
    }

    const auto detail = persistence.detail.empty()
        ? detail_for(change_status)
        : persistence.detail;
    const bool changed = persistence.ok() &&
        persistence.archive_hash != previous_archive_hash;
    return {change_status, std::move(persistence), detail, changed};
}

sx::cfg::ResourceTransformResult ConfigStore::apply_to_content(
    const std::optional<std::string>& content,
    const Change& change,
    ChangeStatus& status) {
    try {
        // No serialized content leaves this function until both the existing
        // resource and requested semantic change have passed validation.
        auto admins = parse(content);
        status = change(admins);

        if(status != ChangeStatus::written) {
            return {
                sx::cfg::ResourceTransformAction::reject,
                {},
                detail_for(status),
            };
        }

        return {
            sx::cfg::ResourceTransformAction::replace,
            admins.serialize(),
            {},
        };
    }
    catch(const std::exception& error) {
        status = ChangeStatus::persistence_error;
        return {
            sx::cfg::ResourceTransformAction::reject,
            {},
            error.what(),
        };
    }
}

ChangeStatus ConfigStore::add_administrator(
    Admins& admins, std::string name, std::string verifier) {
    if(admins.find(name)) {
        return ChangeStatus::already_exists;
    }

    admins.upsert({std::move(name), true, std::move(verifier)});
    return ChangeStatus::written;
}

ChangeStatus ConfigStore::replace_password(
    Admins& admins, std::string name, std::string verifier) {
    const auto* current = admins.find(name);
    if(!current) {
        return ChangeStatus::not_found;
    }

    const bool enabled = current->enabled;
    admins.upsert({std::move(name), enabled, std::move(verifier)});
    return ChangeStatus::written;
}

ChangeStatus ConfigStore::update_enabled(
    Admins& admins, std::string_view name, bool enabled) {
    const auto* current = admins.find(name);
    if(!current) {
        return ChangeStatus::not_found;
    }

    const bool disabling = current->enabled && !enabled;
    const bool final_enabled_administrator = enabled_count(admins) == 1U;
    if(disabling && final_enabled_administrator) {
        return ChangeStatus::last_enabled_administrator;
    }

    const bool unchanged = current->enabled == enabled;
    if(unchanged) {
        return ChangeStatus::written;
    }

    admins.upsert({current->name, enabled, current->password_verifier});
    return ChangeStatus::written;
}

ChangeStatus ConfigStore::erase_administrator(
    Admins& admins, std::string_view name) {
    const auto* current = admins.find(name);
    if(!current) {
        return ChangeStatus::not_found;
    }

    const bool final_enabled_administrator =
        current->enabled && enabled_count(admins) == 1U;
    if(final_enabled_administrator) {
        return ChangeStatus::last_enabled_administrator;
    }

    admins.remove(name);
    return ChangeStatus::written;
}

Admins ConfigStore::parse(std::optional<std::string> content) {
    return content ? Admins::parse(*content) : Admins{};
}

std::size_t ConfigStore::enabled_count(const Admins& admins) noexcept {
    return static_cast<std::size_t>(std::count_if(
        admins.administrators().begin(), admins.administrators().end(),
        [](const Administrator& administrator) { return administrator.enabled; }));
}

} // namespace sx::admin
