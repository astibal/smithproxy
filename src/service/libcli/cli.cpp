#include "cli.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace libcli2 {
namespace {

struct Token {
    std::string value;
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct TokenizeResult {
    std::vector<Token> tokens;
    std::string error;
};

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

TokenizeResult tokenize(std::string_view line, bool allow_incomplete) {
    TokenizeResult result;
    std::size_t cursor = 0;

    while (cursor < line.size()) {
        while (cursor < line.size() && std::isspace(static_cast<unsigned char>(line[cursor]))) ++cursor;
        if (cursor == line.size()) break;

        Token token;
        token.begin = cursor;
        char quote = 0;

        while (cursor < line.size()) {
            const char ch = line[cursor];
            if (ch == '\\' && cursor + 1 < line.size()) {
                token.value.push_back(line[cursor + 1]);
                cursor += 2;
                continue;
            }
            if (quote != 0) {
                if (ch == quote) {
                    quote = 0;
                    ++cursor;
                } else {
                    token.value.push_back(ch);
                    ++cursor;
                }
                continue;
            }
            if (ch == '\'' || ch == '"') {
                quote = ch;
                ++cursor;
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(ch))) break;
            token.value.push_back(ch);
            ++cursor;
        }

        token.end = cursor;
        result.tokens.push_back(std::move(token));
        if (quote != 0 && !allow_incomplete) {
            result.error = "unterminated quote";
            return result;
        }
    }
    return result;
}

std::string join_path(const std::vector<std::string>& parts) {
    std::ostringstream output;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) output << ' ';
        output << parts[i];
    }
    return output.str();
}

std::vector<std::string> names(const std::vector<const Command*>& commands) {
    std::vector<std::string> result;
    result.reserve(commands.size());
    for (const auto* command : commands) result.push_back(command->name());
    return result;
}

}  // namespace

Command::Command(std::string name, Command* parent) : name_(std::move(name)), parent_(parent) {}

Command& Command::help(std::string text) {
    help_ = std::move(text);
    return *this;
}

Command& Command::handler(Handler callback) {
    handler_ = std::move(callback);
    return *this;
}

Command& Command::reset_definition() {
    help_.clear();
    arguments_.clear();
    handler_ = {};
    availability_ = {};
    return *this;
}

Command& Command::argument(Argument specification) {
    if (specification.name.empty()) throw std::invalid_argument("argument name cannot be empty");
    if (!arguments_.empty() && arguments_.back().repeatable)
        throw std::logic_error("a repeatable argument must be the last argument");
    if (specification.required && std::any_of(arguments_.begin(), arguments_.end(),
                           [](const Argument& argument) { return !argument.required; })) {
        throw std::logic_error("a required argument cannot follow an optional argument");
    }
    arguments_.push_back(std::move(specification));
    return *this;
}

Command& Command::available_if(Availability predicate) {
    availability_ = std::move(predicate);
    return *this;
}

Command& Command::find_or_add_child(std::string_view name) {
    const auto found = std::find_if(children_.begin(), children_.end(),
                                    [name](const auto& child) { return child->name_ == name; });
    if (found != children_.end()) return **found;
    children_.push_back(std::unique_ptr<Command>(new Command(std::string(name), this)));
    return *children_.back();
}

std::vector<const Command*> Command::matching_children(std::string_view prefix, const Context& context) const {
    std::vector<const Command*> matches;
    for (const auto& child : children_) {
        if (child->available(context) && starts_with(child->name_, prefix)) matches.push_back(child.get());
    }
    return matches;
}

bool Command::available(const Context& context) const {
    return !availability_ || availability_(context);
}

Cli::Cli() : root_(new Command("")) {}
Cli::~Cli() = default;
Cli::Cli(Cli&&) noexcept = default;
Cli& Cli::operator=(Cli&&) noexcept = default;

Command& Cli::command(std::string_view path) {
    const auto parsed = tokenize(path, false);
    if (!parsed.error.empty() || parsed.tokens.empty()) throw std::invalid_argument("invalid command path");

    Command* current = root_.get();
    for (const auto& token : parsed.tokens) current = &current->find_or_add_child(token.value);
    return *current;
}

ExecuteResult Cli::execute(std::string_view line, Context& context) const {
    const auto parsed = tokenize(line, false);
    if (!parsed.error.empty()) return {ExecuteStatus::invalid_arguments, 0, parsed.error, {}};
    if (parsed.tokens.empty()) return {ExecuteStatus::empty, 0, {}, {}};

    const Command* current = root_.get();
    std::vector<std::string> command_path;
    std::size_t token_index = 0;

    for (; token_index < parsed.tokens.size(); ++token_index) {
        const auto& word = parsed.tokens[token_index].value;
        auto matches = current->matching_children(word, context);
        const auto exact = std::find_if(matches.begin(), matches.end(),
                                        [&word](const Command* command) { return command->name_ == word; });
        if (exact != matches.end()) matches = {*exact};

        if (matches.empty()) break;
        if (matches.size() > 1) {
            return {ExecuteStatus::ambiguous_command, 0, "ambiguous command: " + word, names(matches)};
        }
        current = matches.front();
        command_path.push_back(current->name_);
    }

    if (current == root_.get()) {
        return {ExecuteStatus::unknown_command, 0, "unknown command: " + parsed.tokens.front().value, {}};
    }
    if (!current->handler_) {
        const auto possible = current->matching_children("", context);
        return {ExecuteStatus::incomplete_command, 0, "incomplete command", names(possible)};
    }

    Invocation invocation;
    invocation.command = join_path(command_path);
    invocation.raw_line = std::string(line);
    for (; token_index < parsed.tokens.size(); ++token_index)
        invocation.arguments.push_back(parsed.tokens[token_index].value);

    std::size_t required = 0;
    for (const auto& argument : current->arguments_) required += argument.required ? 1U : 0U;
    const bool repeatable = !current->arguments_.empty() && current->arguments_.back().repeatable;
    if (invocation.arguments.size() < required ||
        (!repeatable && invocation.arguments.size() > current->arguments_.size())) {
        return {ExecuteStatus::invalid_arguments, 0, "invalid number of arguments", {}};
    }
    for (std::size_t i = 0; i < invocation.arguments.size(); ++i) {
        const auto spec_index = std::min(i, current->arguments_.size() - 1);
        const auto& spec = current->arguments_[spec_index];
        if (spec.validate && !spec.validate(invocation.arguments[i])) {
            return {ExecuteStatus::invalid_arguments, 0,
                    "invalid value for <" + spec.name + ">: " + invocation.arguments[i], {}};
        }
    }

    const int status = current->handler_(context, invocation);
    return {status == 0 ? ExecuteStatus::ok : ExecuteStatus::handler_error, status,
            status == 0 ? std::string{} : "command handler failed", {}};
}

CompletionResult Cli::complete(std::string_view line, const Context& context) const {
    const auto parsed = tokenize(line, true);
    CompletionResult result;
    const bool after_space = !line.empty() && std::isspace(static_cast<unsigned char>(line.back()));
    const std::size_t fixed_count = parsed.tokens.size() - ((!after_space && !parsed.tokens.empty()) ? 1U : 0U);
    const std::string_view prefix = (!after_space && !parsed.tokens.empty())
                                        ? std::string_view(parsed.tokens.back().value)
                                        : std::string_view{};
    result.replace_begin = (!after_space && !parsed.tokens.empty()) ? parsed.tokens.back().begin : line.size();
    result.replace_end = line.size();

    const Command* current = root_.get();
    std::vector<std::string> command_path;
    std::size_t index = 0;
    for (; index < fixed_count; ++index) {
        auto matches = current->matching_children(parsed.tokens[index].value, context);
        const auto exact = std::find_if(matches.begin(), matches.end(), [&](const Command* command) {
            return command->name_ == parsed.tokens[index].value;
        });
        if (exact != matches.end()) matches = {*exact};
        if (matches.size() > 1) return result;
        if (matches.empty()) break;
        current = matches.front();
        command_path.push_back(current->name_);
    }

    if (index == fixed_count) {
        const auto children = current->matching_children(prefix, context);
        for (const auto* child : children) result.items.push_back({child->name_, child->help_});
        if (!children.empty()) return result;
    }

    const std::size_t argument_index = fixed_count - index;
    auto run_completer = [&](const Argument& argument) {
        if (argument.complete_contextual) {
            CompletionRequest request{context, join_path(command_path), {}, argument_index, prefix};
            for (std::size_t i = index; i < fixed_count; ++i)
                request.arguments.push_back(parsed.tokens[i].value);
            result.items = argument.complete_contextual(request);
        } else if (argument.complete) {
            result.items = argument.complete(context, prefix);
        }
        result.items.erase(std::remove_if(result.items.begin(), result.items.end(), [&](const CompletionItem& item) {
                               return !starts_with(item.value, prefix);
                           }),
                           result.items.end());
    };
    if (argument_index < current->arguments_.size()) {
        run_completer(current->arguments_[argument_index]);
    } else if (!current->arguments_.empty() && current->arguments_.back().repeatable) {
        run_completer(current->arguments_.back());
    }
    return result;
}

std::string Cli::help(std::string_view path, const Context& context) const {
    const auto parsed = tokenize(path, false);
    const Command* current = root_.get();
    for (const auto& token : parsed.tokens) {
        auto matches = current->matching_children(token.value, context);
        const auto exact = std::find_if(matches.begin(), matches.end(), [&](const Command* command) {
            return command->name_ == token.value;
        });
        if (exact != matches.end()) matches = {*exact};
        if (matches.size() != 1) return {};
        current = matches.front();
    }

    std::ostringstream output;
    if (current != root_.get()) {
        output << current->name_;
        for (const auto& argument : current->arguments_)
            output << ' ' << (argument.required ? '<' : '[') << argument.name << (argument.required ? '>' : ']');
        if (!current->help_.empty()) output << "\n  " << current->help_;
        output << '\n';
        for (const auto& argument : current->arguments_) {
            if (argument.help.empty()) continue;
            output << "  " << (argument.required ? '<' : '[') << argument.name
                   << (argument.required ? '>' : ']') << "\t" << argument.help << '\n';
        }
    }
    for (const auto& child : current->children_) {
        if (!child->available(context)) continue;
        output << "  " << child->name_;
        if (!child->help_.empty()) output << "\t" << child->help_;
        output << '\n';
    }
    return output.str();
}

}  // namespace libcli2
