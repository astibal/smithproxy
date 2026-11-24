#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace sx::admin {

inline constexpr int config_schema_version = 1;

// Administrator identifiers are shared by enrollment, persistent storage,
// and every management transport.
bool valid_name(std::string_view value);

struct Administrator {
    std::string name;
    bool enabled = true;
    std::string password_verifier;

    bool operator==(const Administrator& other) const noexcept;
};

// Owns the typed representation of admin.cfg. Parsing is deliberately strict:
// invalid credentials must never become a partially active configuration.
class Config {
public:
    static Config parse(std::string_view content);

    [[nodiscard]] std::string serialize() const;
    [[nodiscard]] const std::vector<Administrator>& administrators() const noexcept;
    [[nodiscard]] const Administrator* find(std::string_view name) const noexcept;

    void upsert(Administrator administrator);
    bool remove(std::string_view name);

private:
    std::vector<Administrator> administrators_;
};

} // namespace sx::admin
