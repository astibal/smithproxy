#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace libcli2 {

struct Context {
    using Writer = std::function<void(std::string_view)>;

    int privilege = 0;
    std::string mode = "exec";
    void* user_data = nullptr;
    int io_handle = -1;
    Writer write;

    void print(std::string_view text) const {
        if (write) write(text);
    }
};

struct Invocation {
    std::string command;
    std::vector<std::string> arguments;
    std::string raw_line;
};

enum class ExecuteStatus {
    ok,
    empty,
    unknown_command,
    ambiguous_command,
    incomplete_command,
    invalid_arguments,
    handler_error,
};

struct ExecuteResult {
    ExecuteStatus status = ExecuteStatus::ok;
    int handler_status = 0;
    std::string message;
    std::vector<std::string> candidates;

    explicit operator bool() const noexcept { return status == ExecuteStatus::ok; }
};

struct CompletionItem {
    std::string value;
    std::string description;
};

struct CompletionResult {
    std::size_t replace_begin = 0;
    std::size_t replace_end = 0;
    std::vector<CompletionItem> items;
};

using Handler = std::function<int(Context&, const Invocation&)>;
using Completer = std::function<std::vector<CompletionItem>(const Context&, std::string_view)>;
struct CompletionRequest {
    const Context& context;
    std::string command;
    std::vector<std::string> arguments;
    std::size_t argument_index = 0;
    std::string_view prefix;
};
using ContextualCompleter = std::function<std::vector<CompletionItem>(const CompletionRequest&)>;
using Validator = std::function<bool(std::string_view)>;
using Availability = std::function<bool(const Context&)>;

struct Argument {
    Argument(std::string name, std::string help = {}, bool required = true, bool repeatable = false,
             Completer complete = {}, Validator validate = {}, ContextualCompleter complete_contextual = {})
        : name(std::move(name)), help(std::move(help)), required(required), repeatable(repeatable),
          complete(std::move(complete)), validate(std::move(validate)),
          complete_contextual(std::move(complete_contextual)) {}

    std::string name;
    std::string help;
    bool required = true;
    bool repeatable = false;
    Completer complete;
    Validator validate;
    ContextualCompleter complete_contextual;
};

class Command {
public:
    Command& reset_definition();
    Command& help(std::string text);
    Command& handler(Handler callback);
    Command& argument(Argument specification);
    Command& available_if(Availability predicate);

    const std::string& name() const noexcept { return name_; }
    const std::string& description() const noexcept { return help_; }

private:
    explicit Command(std::string name, Command* parent = nullptr);

    Command& find_or_add_child(std::string_view name);
    std::vector<const Command*> matching_children(std::string_view prefix, const Context& context) const;
    bool available(const Context& context) const;

    std::string name_;
    std::string help_;
    Command* parent_ = nullptr;
    std::vector<std::unique_ptr<Command>> children_;
    std::vector<Argument> arguments_;
    Handler handler_;
    Availability availability_;

    friend class Cli;
};

class Cli {
public:
    Cli();
    ~Cli();

    Cli(Cli&&) noexcept;
    Cli& operator=(Cli&&) noexcept;
    Cli(const Cli&) = delete;
    Cli& operator=(const Cli&) = delete;

    Command& command(std::string_view path);
    ExecuteResult execute(std::string_view line, Context& context) const;
    CompletionResult complete(std::string_view line, const Context& context) const;
    std::string help(std::string_view path, const Context& context) const;

private:
    std::unique_ptr<Command> root_;
};

}  // namespace libcli2
