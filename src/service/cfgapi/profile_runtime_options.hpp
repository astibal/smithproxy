#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>
#include <regex>
#include <set>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace cfgapi_detail {

inline std::optional<unsigned short> parse_transport_port(
        std::string_view text) noexcept {
    unsigned int value = 0;
    auto const [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if(error != std::errc{} || end != text.data() + text.size() ||
       value > 65535U) {
        return std::nullopt;
    }
    return static_cast<unsigned short>(value);
}

inline std::optional<unsigned short> offset_transport_port(
        std::string_view text, unsigned int offset) noexcept {
    auto const base = parse_transport_port(text);
    if(!base || offset > 65535U - static_cast<unsigned int>(*base))
        return std::nullopt;
    return static_cast<unsigned short>(static_cast<unsigned int>(*base) + offset);
}

inline bool replacement_redirect_port_matches(
        std::string_view text,
        std::set<int> const* configured_ports = nullptr) noexcept {
    auto const port = parse_transport_port(text);
    if(!port) return false;
    return configured_ports ? configured_ports->count(*port) != 0
                            : *port == 443;
}

template <typename ProfilePtr, typename ConnectionPtr>
bool replacement_redirect_state_complete(ProfilePtr const& profile,
                                         ConnectionPtr* connection) noexcept {
    return static_cast<bool>(profile) && connection != nullptr;
}

inline void replace_sni_bypass_filter(
        std::shared_ptr<std::vector<std::string>>& destination,
        std::shared_ptr<std::vector<std::string>> const& configured) noexcept {
    // Applying a profile is a complete state replacement.  In particular, an
    // absent/empty filter must retire a filter left by an earlier application.
    destination = configured;
}

template <typename ProfilePtr>
bool dns_sni_bypass_state_complete(ProfilePtr const& profile) noexcept {
    if(!profile) return false;
    if(!profile->sni_filter_use_dns_cache || !profile->sni_filter_bypass ||
       profile->sni_filter_bypass->empty())
        return true;
    return profile->sni_filter_bypass_addrobj &&
           profile->sni_filter_bypass_addrobj->size() ==
               profile->sni_filter_bypass->size();
}

template <typename CertificateOptions>
void replace_peer_replacement_state(CertificateOptions& destination,
                                    bool configured,
                                    bool port_eligible) noexcept {
    destination.failed_check_replacement = configured && port_eligible;
}

inline bool fail_open_setting(bool loaded, bool configured) noexcept {
    // Missing or malformed configuration must retire any value retained from
    // an older generation; fail-open is active only when explicitly loaded.
    return loaded && configured;
}

inline bool valid_content_rule_pattern(std::string const& pattern) noexcept {
    if(pattern.empty()) return false;
    try {
        const std::regex compiled(pattern);
        (void)compiled;
        return true;
    } catch(std::regex_error const&) {
        return false;
    }
}

inline bool policy_dependency_section(std::string_view section) noexcept {
    constexpr std::array<std::string_view, 11> dependencies {
        "proto_objects", "port_objects", "address_objects",
        "detection_profiles", "content_profiles", "tls_profiles",
        "ssh_profiles", "alg_dns_profiles", "script_profiles",
        "auth_profiles", "routing",
    };
    return std::find(dependencies.begin(), dependencies.end(), section) !=
           dependencies.end();
}

template <typename ProfilePtr>
std::string profile_name_or(ProfilePtr const& profile,
                            std::string_view fallback = "none") {
    return profile ? profile->element_name() : std::string(fallback);
}

template <typename Policy>
std::string_view policy_action_for_save(Policy const& policy) noexcept {
    // A degraded rule already runs as a fail-closed DENY. Its configured
    // action may still say "accept"; serializing that value together with
    // wildcarded missing selectors would turn a later reload into an allow.
    return policy.cfg_err_is_degraded ? std::string_view("deny")
                                      : std::string_view(policy.action_name);
}

template <typename Profile, typename Loader>
void load_pfs_options(Profile& profile, Loader&& load) {
    load("use_pfs", profile.use_pfs);

    // The common switch is the baseline.  Directional values are optional
    // overrides, so an omitted one must not silently recover its constructor
    // default and erase the configured common policy.
    profile.left_use_pfs = profile.use_pfs;
    profile.right_use_pfs = profile.use_pfs;
    load("left_use_pfs", profile.left_use_pfs);
    load("right_use_pfs", profile.right_use_pfs);
}

template <typename DependencyReload, typename PolicyReload>
bool reload_policy_dependency(DependencyReload&& reload_dependency,
                              PolicyReload&& reload_policy) {
    const bool dependency_result = static_cast<bool>(reload_dependency());
    // A zero-sized dependency database is a valid state transition even
    // though legacy loaders report it as false. Policies must still be
    // rebuilt so they cannot retain shared_ptrs into the previous generation.
    const bool policy_result = static_cast<bool>(reload_policy());
    return dependency_result && policy_result;
}

template <typename AccountingOptions, typename HttpOptions>
void apply_ja4_http_option(bool enabled,
                           AccountingOptions& accounting,
                           HttpOptions& http) {
    accounting.ja4_http = enabled;
    http.ja4h = enabled;
}

template <typename Setting, typename ContentRule>
void save_content_rule(Setting& destination, ContentRule const& rule) {
    destination.add("match", Setting::TypeString) = rule.match;
    destination.add("replace", Setting::TypeString) = rule.replace;
    destination.add("fill_length", Setting::TypeBoolean) = rule.fill_length;
    destination.add("replace_each_nth", Setting::TypeInt) = rule.replace_each_nth;
}

} // namespace cfgapi_detail
