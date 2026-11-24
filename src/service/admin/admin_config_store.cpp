#include "admin_config_store.hpp"

#include <service/cfgapi/cfg_archive.hpp>
#include <utils/crypto.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::string_view admin_config_path = "admin.cfg";

std::string detail_for(sx::admin::MutationStatus status) {
    using Status = sx::admin::MutationStatus;
    switch(status) {
        case Status::written: return {};
        case Status::invalid_name: return "administrator name is invalid";
        case Status::invalid_password: return "administrator password is invalid";
        case Status::already_exists: return "administrator already exists";
        case Status::not_found: return "administrator does not exist";
        case Status::last_enabled_administrator:
            return "the final enabled administrator cannot be disabled or removed";
        case Status::persistence_error: return "administrator configuration was not written";
    }
    return "administrator configuration was not written";
}

} // namespace

namespace sx::admin {

ConfigStore::ConfigStore(Context context): context_(context) {}

Config ConfigStore::read() const {
    const auto guard = std::scoped_lock(context_.config_mutex);
    if(!context_.archive.available())
        throw std::runtime_error("native configuration archive is unavailable");

    const auto archive = sx::cfg::CfgArchive::read_archive(
        sx::cfg::smithproxy_schema(), "active.cftar", context_.archive.current());
    if(!archive.archive().contains(admin_config_path)) return {};
    return Config::parse(archive.archive().at(admin_config_path).data);
}

MutationResult ConfigStore::create(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string name,
    std::string_view password) {
    if(!valid_name(name))
        return {MutationStatus::invalid_name, {}, detail_for(MutationStatus::invalid_name)};
    auto verifier = sx::crypto::password_verifier(password);
    if(!verifier)
        return {MutationStatus::invalid_password, {}, detail_for(MutationStatus::invalid_password)};

    return mutate(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::move(name), verifier = std::move(*verifier)](Config& config) mutable {
            if(config.find(name)) return MutationStatus::already_exists;
            config.upsert({std::move(name), true, std::move(verifier)});
            return MutationStatus::written;
        });
}

MutationResult ConfigStore::change_password(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name,
    std::string_view password) {
    if(!valid_name(name))
        return {MutationStatus::invalid_name, {}, detail_for(MutationStatus::invalid_name)};
    auto verifier = sx::crypto::password_verifier(password);
    if(!verifier)
        return {MutationStatus::invalid_password, {}, detail_for(MutationStatus::invalid_password)};

    return mutate(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name), verifier = std::move(*verifier)](Config& config) mutable {
            const auto* current = config.find(name);
            if(!current) return MutationStatus::not_found;
            config.upsert({std::move(name), current->enabled, std::move(verifier)});
            return MutationStatus::written;
        });
}

MutationResult ConfigStore::set_enabled(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name,
    bool enabled) {
    if(!valid_name(name))
        return {MutationStatus::invalid_name, {}, detail_for(MutationStatus::invalid_name)};

    return mutate(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name), enabled](Config& config) {
            const auto* current = config.find(name);
            if(!current) return MutationStatus::not_found;
            if(current->enabled && !enabled && enabled_count(config) == 1U)
                return MutationStatus::last_enabled_administrator;
            if(current->enabled == enabled) return MutationStatus::written;
            config.upsert({current->name, enabled, current->password_verifier});
            return MutationStatus::written;
        });
}

MutationResult ConfigStore::remove(
    std::string expected_revision,
    std::string expected_archive_hash,
    std::string_view name) {
    if(!valid_name(name))
        return {MutationStatus::invalid_name, {}, detail_for(MutationStatus::invalid_name)};

    return mutate(
        std::move(expected_revision), std::move(expected_archive_hash),
        [name = std::string(name)](Config& config) {
            const auto* current = config.find(name);
            if(!current) return MutationStatus::not_found;
            if(current->enabled && enabled_count(config) == 1U)
                return MutationStatus::last_enabled_administrator;
            config.remove(name);
            return MutationStatus::written;
        });
}

MutationResult ConfigStore::mutate(
    std::string expected_revision,
    std::string expected_archive_hash,
    Mutation mutation) {
    MutationStatus mutation_status = MutationStatus::persistence_error;
    sx::cfg::CfgResourceWriter writer({
        context_.board, context_.gate, context_.config_mutex, context_.archive,
    });
    auto persistence = writer.transform(
        std::move(expected_revision), std::move(expected_archive_hash),
        std::string(admin_config_path),
        [&mutation, &mutation_status](std::optional<std::string> content) {
            try {
                auto config = parse(std::move(content));
                mutation_status = mutation(config);
                if(mutation_status != MutationStatus::written) {
                    return sx::cfg::ResourceTransformResult{
                        false, {}, detail_for(mutation_status)};
                }
                return sx::cfg::ResourceTransformResult{
                    true, config.serialize(), {}};
            }
            catch(const std::exception& error) {
                mutation_status = MutationStatus::persistence_error;
                return sx::cfg::ResourceTransformResult{false, {}, error.what()};
            }
        },
        false,
        sx::cfg::ResourceActivation::immediate);

    if(!persistence.ok() && mutation_status == MutationStatus::written)
        mutation_status = MutationStatus::persistence_error;
    const auto detail = persistence.detail.empty()
        ? detail_for(mutation_status)
        : persistence.detail;
    return {mutation_status, std::move(persistence), detail};
}

Config ConfigStore::parse(std::optional<std::string> content) {
    return content ? Config::parse(*content) : Config{};
}

std::size_t ConfigStore::enabled_count(const Config& config) noexcept {
    return static_cast<std::size_t>(std::count_if(
        config.administrators().begin(), config.administrators().end(),
        [](const Administrator& administrator) { return administrator.enabled; }));
}

} // namespace sx::admin
