#include "cli.hpp"
#include "line_editor.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::string trim_right(std::string text) {
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.pop_back();
    return text;
}

void print_completion(const libcli2::Cli& cli, const libcli2::Context& context, std::string line) {
    if (!line.empty() && line.back() == '?') line.pop_back();
    const auto completion = cli.complete(line, context);

    if (completion.items.empty()) {
        std::cout << "  (no matches)\n";
        return;
    }

    std::cout << "  replace [" << completion.replace_begin << ", " << completion.replace_end << "):\n";
    for (const auto& item : completion.items) {
        std::cout << "    " << item.value;
        if (!item.description.empty()) std::cout << "\t" << item.description;
        std::cout << '\n';
    }
}

void print_error(const libcli2::ExecuteResult& result) {
    if (!result.message.empty()) std::cout << "% " << result.message << '\n';
    if (!result.candidates.empty()) {
        std::cout << "  candidates:";
        for (const auto& candidate : result.candidates) std::cout << ' ' << candidate;
        std::cout << '\n';
    }
}

}  // namespace

int main() {
    using namespace libcli2;

    Cli cli;
    Context context;
    bool running = true;
    const std::vector<std::string> session_ids{"alpha", "beta", "client-42"};

    context.write = [](std::string_view text) { std::cout << text << '\n'; };

    cli.command("show status")
        .help("Show demo status")
        .handler([](Context& ctx, const Invocation&) {
            ctx.print("status: running, mode=" + ctx.mode + ", privilege=" + std::to_string(ctx.privilege));
            return 0;
        });

    cli.command("show sessions")
        .help("List known sessions")
        .handler([&](Context& ctx, const Invocation&) {
            for (const auto& id : session_ids) ctx.print(id);
            return 0;
        });

    cli.command("show session")
        .help("Show one session")
        .argument({"id", "Session ID", true, false,
                   [&](const Context&, std::string_view prefix) {
                       std::vector<CompletionItem> matches;
                       for (const auto& id : session_ids) {
                           if (id.compare(0, prefix.size(), prefix) == 0)
                               matches.push_back({id, "active session"});
                       }
                       return matches;
                   },
                   [&](std::string_view value) {
                       return std::find(session_ids.begin(), session_ids.end(), value) != session_ids.end();
                   }})
        .handler([](Context& ctx, const Invocation& call) {
            ctx.print("session " + call.arguments.at(0) + ": 127.0.0.1 -> example.test:443");
            return 0;
        });

    cli.command("echo")
        .help("Echo one or more arguments")
        .argument({"text", "Text to print", true, true})
        .handler([](Context& ctx, const Invocation& call) {
            std::string output;
            for (const auto& argument : call.arguments) {
                if (!output.empty()) output += ' ';
                output += argument;
            }
            ctx.print(output);
            return 0;
        });

    cli.command("enable")
        .help("Gain privileged access")
        .available_if([](const Context& ctx) { return ctx.privilege < 15; })
        .handler([](Context& ctx, const Invocation&) {
            ctx.privilege = 15;
            ctx.print("privileged mode enabled");
            return 0;
        });

    cli.command("configure terminal")
        .help("Enter configuration mode")
        .available_if([](const Context& ctx) { return ctx.privilege >= 15 && ctx.mode == "exec"; })
        .handler([](Context& ctx, const Invocation&) {
            ctx.mode = "config";
            return 0;
        });

    cli.command("end")
        .help("Return to exec mode")
        .available_if([](const Context& ctx) { return ctx.mode == "config"; })
        .handler([](Context& ctx, const Invocation&) {
            ctx.mode = "exec";
            return 0;
        });

    cli.command("quit").help("Exit the demo").handler([&](Context&, const Invocation&) {
        running = false;
        return 0;
    });

    std::cout << "libcli2 demo\n"
                 "Try: sh st | show s | show session ? | enable | conf t | end\n"
                 "Use: ? or <partial command>? for completion, help [path], quit\n\n";

    LineEditor editor(cli, context);
    std::string line;
    while (running) {
        const auto input = editor.read_line("demo(" + context.mode + ")" + (context.privilege >= 15 ? "# " : "> "));
        if (!input) break;
        line = *input;

        if (!line.empty() && line.back() == '?') {
            print_completion(cli, context, line);
            continue;
        }
        if (line == "help") {
            std::cout << cli.help("", context);
            continue;
        }
        if (line.compare(0, 5, "help ") == 0) {
            const auto text = cli.help(trim_right(line.substr(5)), context);
            std::cout << (text.empty() ? "% unknown or ambiguous help path\n" : text);
            continue;
        }

        const auto result = cli.execute(line, context);
        if (result.status != ExecuteStatus::ok && result.status != ExecuteStatus::empty) print_error(result);
    }
}
