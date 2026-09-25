#include "line_editor.hpp"

#include <algorithm>
#include <cerrno>
#include <iostream>
#include <termios.h>
#include <unistd.h>

namespace libcli2 {
namespace {

class RawTerminal {
public:
    RawTerminal() {
        if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &saved_) != 0) return;
        auto raw = saved_;
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_iflag &= static_cast<tcflag_t>(~(ICRNL | IXON));
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0;
    }

    ~RawTerminal() {
        if (active_) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
    }

    bool active() const noexcept { return active_; }

private:
    termios saved_{};
    bool active_ = false;
};

bool read_byte(char& value) {
    while (true) {
        const auto count = ::read(STDIN_FILENO, &value, 1);
        if (count == 1) return true;
        if (count == 0) return false;
        if (errno != EINTR) return false;
    }
}

std::string common_prefix(const std::vector<CompletionItem>& items) {
    if (items.empty()) return {};
    std::string prefix = items.front().value;
    for (std::size_t i = 1; i < items.size(); ++i) {
        const auto mismatch = std::mismatch(prefix.begin(), prefix.end(), items[i].value.begin(), items[i].value.end());
        prefix.erase(static_cast<std::size_t>(mismatch.first - prefix.begin()));
    }
    return prefix;
}

}  // namespace

LineEditor::LineEditor(const Cli& cli, const Context& context) : cli_(cli), context_(context) {}

void LineEditor::add_history(std::string line) {
    if (line.empty() || (!history_.empty() && history_.back() == line)) return;
    history_.push_back(std::move(line));
    constexpr std::size_t max_history = 256;
    if (history_.size() > max_history) history_.erase(history_.begin());
}

void LineEditor::redraw(std::string_view prompt, std::string_view line, std::size_t cursor) const {
    std::cout << "\r\033[2K" << prompt << line;
    if (cursor < line.size()) std::cout << "\033[" << (line.size() - cursor) << 'D';
    std::cout.flush();
}

void LineEditor::show_candidates(const CompletionResult& completion) const {
    if (completion.items.empty()) {
        std::cout << "\r\n  (no matches)\r\n";
        return;
    }
    std::cout << "\r\n";
    for (const auto& item : completion.items) {
        std::cout << "  " << item.value;
        if (!item.description.empty()) std::cout << "\t" << item.description;
        std::cout << "\r\n";
    }
}

bool LineEditor::apply_completion(std::string& line, std::size_t& cursor, bool list_if_ambiguous) const {
    const auto completion = cli_.complete(std::string_view(line).substr(0, cursor), context_);
    if (completion.items.empty()) {
        if (list_if_ambiguous) show_candidates(completion);
        return list_if_ambiguous;
    }

    const auto replacement = completion.items.size() == 1 ? completion.items.front().value
                                                           : common_prefix(completion.items);
    const auto old_length = cursor - completion.replace_begin;
    bool changed = replacement.size() > old_length;
    if (changed || completion.items.size() == 1) {
        line.replace(completion.replace_begin, old_length, replacement);
        cursor = completion.replace_begin + replacement.size();
        if (completion.items.size() == 1 && (cursor == line.size() || line[cursor] != ' ')) {
            line.insert(cursor, 1, ' ');
            ++cursor;
        }
        changed = true;
    }
    if (completion.items.size() > 1 && list_if_ambiguous && !changed) show_candidates(completion);
    return changed || (list_if_ambiguous && completion.items.size() > 1);
}

std::optional<std::string> LineEditor::read_line(std::string_view prompt) {
    RawTerminal terminal;
    if (!terminal.active()) {
        std::cout << prompt;
        std::string line;
        if (!std::getline(std::cin, line)) return std::nullopt;
        add_history(line);
        return line;
    }

    std::string line;
    std::string saved_line;
    std::size_t cursor = 0;
    std::size_t history_index = history_.size();
    std::cout << prompt << std::flush;

    while (true) {
        char key = 0;
        if (!read_byte(key)) return std::nullopt;

        if (key == '\r' || key == '\n') {
            std::cout << "\r\n";
            add_history(line);
            return line;
        }
        if (key == 4) {  // Ctrl-D
            if (line.empty()) {
                std::cout << "\r\n";
                return std::nullopt;
            }
            continue;
        }
        if (key == 1) {  // Ctrl-A
            cursor = 0;
        } else if (key == 5) {  // Ctrl-E
            cursor = line.size();
        } else if (key == 21) {  // Ctrl-U
            line.erase(0, cursor);
            cursor = 0;
        } else if (key == 127 || key == 8) {
            if (cursor > 0) line.erase(--cursor, 1);
        } else if (key == '\t') {
            apply_completion(line, cursor, true);
        } else if (key == '?') {
            const auto completion = cli_.complete(std::string_view(line).substr(0, cursor), context_);
            if (!completion.items.empty()) {
                show_candidates(completion);
            } else {
                auto path = line.substr(0, cursor);
                while (!path.empty() && path.back() == ' ') path.pop_back();
                const auto help = cli_.help(path, context_);
                if (help.empty())
                    show_candidates(completion);
                else
                    std::cout << "\r\n" << help;
            }
        } else if (key == 27) {
            char first = 0;
            char second = 0;
            if (!read_byte(first) || first != '[' || !read_byte(second)) continue;
            if (second == 'C' && cursor < line.size()) ++cursor;
            if (second == 'D' && cursor > 0) --cursor;
            if (second == 'A' && !history_.empty() && history_index > 0) {
                if (history_index == history_.size()) saved_line = line;
                line = history_[--history_index];
                cursor = line.size();
            }
            if (second == 'B' && history_index < history_.size()) {
                ++history_index;
                line = history_index == history_.size() ? saved_line : history_[history_index];
                cursor = line.size();
            }
        } else if (static_cast<unsigned char>(key) >= 32) {
            line.insert(cursor++, 1, key);
        }
        redraw(prompt, line, cursor);
    }
}

}  // namespace libcli2
