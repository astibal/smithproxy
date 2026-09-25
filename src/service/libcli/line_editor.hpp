#pragma once

#include "cli.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace libcli2 {

class LineEditor {
public:
    LineEditor(const Cli& cli, const Context& context);

    std::optional<std::string> read_line(std::string_view prompt);
    void add_history(std::string line);

private:
    void redraw(std::string_view prompt, std::string_view line, std::size_t cursor) const;
    void show_candidates(const CompletionResult& completion) const;
    bool apply_completion(std::string& line, std::size_t& cursor, bool list_if_ambiguous) const;

    const Cli& cli_;
    const Context& context_;
    std::vector<std::string> history_;
};

}  // namespace libcli2
