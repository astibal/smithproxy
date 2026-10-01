#pragma once

#include <array>
#include <string>
#include <string_view>

namespace libcli2 {

enum class ColorMode { automatic, on, off };
enum class ColorTheme { classic, solarized, monokai, nord, gruvbox, matrix, monochrome, amber, ice };

inline constexpr std::array<std::string_view, 9> color_theme_names{
    "classic", "solarized", "monokai", "nord", "gruvbox", "matrix", "monochrome", "amber", "ice"
};

inline constexpr std::string_view color_theme_name(ColorTheme theme) noexcept {
    return color_theme_names[static_cast<std::size_t>(theme)];
}

inline bool parse_color_theme(std::string_view name, ColorTheme& theme) noexcept {
    for (std::size_t index = 0; index < color_theme_names.size(); ++index) {
        if (color_theme_names[index] == name) {
            theme = static_cast<ColorTheme>(index);
            return true;
        }
    }
    return false;
}

enum class Style {
    plain,
    heading,
    command,
    key,
    value,
    success,
    warning,
    error,
    muted,
};

class Decorator {
public:
    explicit Decorator(bool enabled = false, ColorTheme theme = ColorTheme::classic)
        : enabled_(enabled), theme_(theme) {}

    std::string operator()(Style style, std::string_view text) const {
        if (!enabled_ || style == Style::plain || text.empty()) return std::string(text);
        return std::string(code(theme_, style)) + std::string(text) + std::string(reset());
    }

    std::string heading(std::string_view text) const { return (*this)(Style::heading, text); }
    std::string command(std::string_view text) const { return (*this)(Style::command, text); }
    std::string key(std::string_view text) const { return (*this)(Style::key, text); }
    std::string value(std::string_view text) const { return (*this)(Style::value, text); }
    std::string success(std::string_view text) const { return (*this)(Style::success, text); }
    std::string warning(std::string_view text) const { return (*this)(Style::warning, text); }
    std::string error(std::string_view text) const { return (*this)(Style::error, text); }
    std::string muted(std::string_view text) const { return (*this)(Style::muted, text); }

    bool enabled() const noexcept { return enabled_; }

private:
    static constexpr std::string_view classic(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;36m";
            case Style::command: return "\033[36m";
            case Style::key: return "\033[2;36m";
            case Style::value: return "\033[1;37m";
            case Style::success: return "\033[32m";
            case Style::warning: return "\033[33m";
            case Style::error: return "\033[1;31m";
            case Style::muted: return "\033[2;37m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view solarized(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;42;161;152m";
            case Style::command: return "\033[38;2;38;139;210m";
            case Style::key: return "\033[38;2;42;161;152m";
            case Style::value: return "\033[1;38;2;238;232;213m";
            case Style::success: return "\033[38;2;133;153;0m";
            case Style::warning: return "\033[38;2;181;137;0m";
            case Style::error: return "\033[1;38;2;220;50;47m";
            case Style::muted: return "\033[38;2;101;123;131m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view monokai(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;102;217;239m";
            case Style::command: return "\033[38;2;102;217;239m";
            case Style::key: return "\033[38;2;174;129;255m";
            case Style::value: return "\033[1;38;2;248;248;242m";
            case Style::success: return "\033[38;2;166;226;46m";
            case Style::warning: return "\033[38;2;230;219;116m";
            case Style::error: return "\033[1;38;2;249;38;114m";
            case Style::muted: return "\033[38;2;117;113;94m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view nord(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;136;192;208m";
            case Style::command: return "\033[38;2;129;161;193m";
            case Style::key: return "\033[38;2;143;188;187m";
            case Style::value: return "\033[1;38;2;236;239;244m";
            case Style::success: return "\033[38;2;163;190;140m";
            case Style::warning: return "\033[38;2;235;203;139m";
            case Style::error: return "\033[1;38;2;191;97;106m";
            case Style::muted: return "\033[38;2;97;110;136m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view gruvbox(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;142;192;124m";
            case Style::command: return "\033[38;2;131;165;152m";
            case Style::key: return "\033[38;2;211;134;155m";
            case Style::value: return "\033[1;38;2;235;219;178m";
            case Style::success: return "\033[38;2;184;187;38m";
            case Style::warning: return "\033[38;2;250;189;47m";
            case Style::error: return "\033[1;38;2;251;73;52m";
            case Style::muted: return "\033[38;2;146;131;116m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view matrix(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;130;255;126m";
            case Style::command: return "\033[38;2;65;255;99m";
            case Style::key: return "\033[2;38;2;94;220;106m";
            case Style::value: return "\033[1;38;2;210;255;208m";
            case Style::success: return "\033[38;2;46;255;78m";
            case Style::warning: return "\033[1;38;2;169;255;143m";
            case Style::error: return "\033[1;38;2;220;255;218m";
            case Style::muted: return "\033[2;38;2;62;142;72m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view monochrome(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;245;245;245m";
            case Style::command: return "\033[38;2;220;220;220m";
            case Style::key: return "\033[2;38;2;205;205;205m";
            case Style::value: return "\033[1;38;2;255;255;255m";
            case Style::success: return "\033[38;2;230;230;230m";
            case Style::warning: return "\033[1;38;2;250;250;250m";
            case Style::error: return "\033[1;38;2;255;255;255m";
            case Style::muted: return "\033[2;38;2;150;150;150m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view amber(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;255;193;77m";
            case Style::command: return "\033[38;2;255;176;46m";
            case Style::key: return "\033[2;38;2;230;146;24m";
            case Style::value: return "\033[1;38;2;255;224;159m";
            case Style::success: return "\033[38;2;255;184;56m";
            case Style::warning: return "\033[1;38;2;255;205;112m";
            case Style::error: return "\033[1;38;2;255;232;184m";
            case Style::muted: return "\033[2;38;2;166;105;25m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view ice(Style style) noexcept {
        switch (style) {
            case Style::heading: return "\033[1;38;2;151;246;255m";
            case Style::command: return "\033[38;2;92;224;235m";
            case Style::key: return "\033[2;38;2;94;196;207m";
            case Style::value: return "\033[1;38;2;224;252;255m";
            case Style::success: return "\033[38;2;112;232;241m";
            case Style::warning: return "\033[1;38;2;174;245;250m";
            case Style::error: return "\033[1;38;2;235;253;255m";
            case Style::muted: return "\033[2;38;2;73;139;148m";
            case Style::plain: break;
        }
        return {};
    }

    static constexpr std::string_view code(ColorTheme theme, Style style) noexcept {
        switch (theme) {
            case ColorTheme::classic: return classic(style);
            case ColorTheme::solarized: return solarized(style);
            case ColorTheme::monokai: return monokai(style);
            case ColorTheme::nord: return nord(style);
            case ColorTheme::gruvbox: return gruvbox(style);
            case ColorTheme::matrix: return matrix(style);
            case ColorTheme::monochrome: return monochrome(style);
            case ColorTheme::amber: return amber(style);
            case ColorTheme::ice: return ice(style);
        }
        return {};
    }

    static constexpr std::string_view reset() noexcept { return "\033[0m"; }

    bool enabled_ = false;
    ColorTheme theme_ = ColorTheme::classic;
};

}  // namespace libcli2
