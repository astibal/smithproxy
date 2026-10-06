#include "cli.hpp"
#include "line_editor.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <fcntl.h>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace libcli2 {
namespace {

struct ScopedStreamBuffer {
    explicit ScopedStreamBuffer(std::ostream& stream, std::streambuf* replacement)
        : stream(stream), original(stream.rdbuf(replacement)) {}
    ~ScopedStreamBuffer() { stream.rdbuf(original); }

    std::ostream& stream;
    std::streambuf* original;
};

struct ScopedInputBuffer {
    explicit ScopedInputBuffer(std::istream& stream, std::streambuf* replacement)
        : stream(stream), original(stream.rdbuf(replacement)) {
        stream.clear();
    }
    ~ScopedInputBuffer() {
        stream.rdbuf(original);
        stream.clear();
    }

    std::istream& stream;
    std::streambuf* original;
};

struct ScopedStdinFd {
    ScopedStdinFd() : saved(::dup(STDIN_FILENO)) {}
    ~ScopedStdinFd() {
        if (saved >= 0) {
            ::dup2(saved, STDIN_FILENO);
            ::close(saved);
        }
    }

    bool replace_with(int fd) const { return ::dup2(fd, STDIN_FILENO) >= 0; }
    int saved = -1;
};

std::optional<std::string> read_from_pseudoterminal(
    LineEditor& editor, std::string_view input) {
    const int master = ::posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || ::grantpt(master) != 0 || ::unlockpt(master) != 0) {
        if (master >= 0) ::close(master);
        return std::nullopt;
    }
    const char* slave_name = ::ptsname(master);
    if (!slave_name) {
        ::close(master);
        return std::nullopt;
    }
    const int slave = ::open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        ::close(master);
        return std::nullopt;
    }

    ScopedStdinFd stdin_guard;
    if (stdin_guard.saved < 0 || !stdin_guard.replace_with(slave)) {
        ::close(slave);
        ::close(master);
        return std::nullopt;
    }
    ::close(slave);
    std::thread writer([master, bytes = std::string(input)] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto written = ::write(master, bytes.data() + offset,
                                         bytes.size() - offset);
            if (written <= 0) break;
            offset += static_cast<std::size_t>(written);
        }
    });
    auto result = editor.read_line("tty> ");
    writer.join();
    ::close(master);
    return result;
}

}  // namespace

struct LineEditorTestAccess {
    static bool apply_completion(LineEditor& editor, std::string& line,
                                 std::size_t& cursor, bool list_if_ambiguous) {
        return editor.apply_completion(line, cursor, list_if_ambiguous);
    }

    static void redraw(LineEditor const& editor, std::string_view prompt,
                       std::string_view line, std::size_t cursor) {
        editor.redraw(prompt, line, cursor);
    }

    static std::vector<std::string> const& history(LineEditor const& editor) {
        return editor.history_;
    }
};

namespace {

TEST(Libcli2, ExecutesUniquePrefixesAndParsesQuotedArguments) {
    Cli cli;
    Invocation seen;
    cli.command("show session")
        .argument({"id", "Session identifier"})
        .handler([&](Context&, const Invocation& invocation) {
            seen = invocation;
            return 0;
        });

    Context context;
    const auto result = cli.execute("sh ses 'client 7'", context);

    ASSERT_TRUE(result);
    EXPECT_EQ(seen.command, "show session");
    ASSERT_EQ(seen.arguments.size(), 1U);
    EXPECT_EQ(seen.arguments.front(), "client 7");
}

TEST(Libcli2, ReportsAmbiguousPrefixes) {
    Cli cli;
    cli.command("show sessions").handler([](Context&, const Invocation&) { return 0; });
    cli.command("show status").handler([](Context&, const Invocation&) { return 0; });

    Context context;
    const auto result = cli.execute("show s", context);

    EXPECT_EQ(result.status, ExecuteStatus::ambiguous_command);
    EXPECT_EQ(result.candidates, (std::vector<std::string>{"sessions", "status"}));
}

TEST(Libcli2, CompletesCommandsAndArguments) {
    Cli cli;
    cli.command("show session")
        .argument({"id", "Session identifier", true, false,
                   [](const Context&, std::string_view prefix) {
                       std::vector<CompletionItem> result;
                       for (const std::string value : {"alpha", "beta"})
                           if (value.compare(0, prefix.size(), prefix) == 0) result.push_back({value, {}});
                       return result;
                   }})
        .handler([](Context&, const Invocation&) { return 0; });

    Context context;
    const auto commands = cli.complete("sh", context);
    ASSERT_EQ(commands.items.size(), 1U);
    EXPECT_EQ(commands.items.front().value, "show");
    EXPECT_EQ(commands.replace_begin, 0U);

    const auto arguments = cli.complete("show session a", context);
    ASSERT_EQ(arguments.items.size(), 1U);
    EXPECT_EQ(arguments.items.front().value, "alpha");
    EXPECT_EQ(arguments.replace_begin, 13U);

    const auto second_argument = cli.complete("show session alpha ", context);
    EXPECT_TRUE(second_argument.items.empty());
}

TEST(Libcli2, CompletionPrefixRemainsValidDuringLookup) {
    Cli cli;
    cli.command("diagnostics").handler([](Context&, const Invocation&) { return 0; });

    Context context;
    const auto result = cli.complete("diag", context);

    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items.front().value, "diagnostics");
}

TEST(Libcli2, AvailabilityCanModelModesAndPrivileges) {
    Cli cli;
    cli.command("configure")
        .available_if([](const Context& context) { return context.privilege >= 15 && context.mode == "exec"; })
        .handler([](Context&, const Invocation&) { return 0; });

    Context context;
    EXPECT_EQ(cli.execute("configure", context).status, ExecuteStatus::unknown_command);
    context.privilege = 15;
    EXPECT_TRUE(cli.execute("configure", context));
}

TEST(Libcli2, ValidatesArgumentsAndGeneratesHelp) {
    Cli cli;
    cli.command("show session")
        .help("Show one session")
        .argument({"id", "Session identifier", true, false, {},
                   [](std::string_view value) { return !value.empty() && value.front() == '#'; }})
        .handler([](Context&, const Invocation&) { return 0; });
    cli.command("show sessions").help("List sessions").handler([](Context&, const Invocation&) { return 0; });

    Context context;
    EXPECT_EQ(cli.execute("show session 42", context).status, ExecuteStatus::invalid_arguments);
    EXPECT_TRUE(cli.execute("show session #42", context));

    const auto text = cli.help("show session", context);
    EXPECT_NE(text.find("session <id>"), std::string::npos);
    EXPECT_NE(text.find("Show one session"), std::string::npos);
}

TEST(Libcli2, ContextualCompletionSeesEarlierArguments) {
    Cli cli;
    cli.command("set")
        .argument({"property", "Property name", true, false, {}, {},
                   [](const CompletionRequest&) {
                       return std::vector<CompletionItem>{{"protocol", {}}};
                   }})
        .argument({"value", "New value", true, false, {}, {},
                   [](const CompletionRequest& request) {
                       if (request.arguments == std::vector<std::string>{"protocol"})
                           return std::vector<CompletionItem>{{"tcp", {}}, {"udp", {}}};
                       return std::vector<CompletionItem>{};
                   }})
        .handler([](Context&, const Invocation&) { return 0; });

    Context context;
    const auto values = cli.complete("set protocol t", context);
    ASSERT_EQ(values.items.size(), 1U);
    EXPECT_EQ(values.items.front().value, "tcp");
}

TEST(Libcli2, ResetDefinitionReplacesImportedCommandMetadata) {
    Cli cli;
    cli.command("show config")
        .help("legacy")
        .argument({"arguments", {}, false, true})
        .available_if([](const Context&) { return false; })
        .handler([](Context&, const Invocation&) { return -1; });

    cli.command("show config")
        .reset_definition()
        .help("native")
        .handler([](Context&, const Invocation&) { return 0; });

    Context context;
    EXPECT_TRUE(cli.execute("show config", context));
    EXPECT_EQ(cli.execute("show config unexpected", context).status, ExecuteStatus::invalid_arguments);
    EXPECT_NE(cli.help("show config", context).find("native"), std::string::npos);
}

TEST(Libcli2, DecoratorIsPlainByDefault) {
    Context context;
    const auto decor = context.decor();

    EXPECT_FALSE(decor.enabled());
    EXPECT_EQ(decor.error("FAILED"), "FAILED");
    EXPECT_EQ(decor.command("show status"), "show status");
}

TEST(Libcli2, DecoratorUsesSemanticAnsiStylesWhenEnabled) {
    Context context;
    context.color_capable = true;
    context.color_mode = ColorMode::automatic;
    const auto decor = context.decor();

    EXPECT_TRUE(decor.enabled());
    EXPECT_EQ(decor.success("OK"), "\033[32mOK\033[0m");
    EXPECT_EQ(decor.error("FAILED"), "\033[1;31mFAILED\033[0m");
    EXPECT_EQ(decor.key("policy"), "\033[2;36mpolicy\033[0m");

    context.color_mode = ColorMode::off;
    EXPECT_EQ(context.decor().warning("warning"), "warning");
    context.color_mode = ColorMode::on;
    EXPECT_EQ(context.decor().warning("warning"), "\033[33mwarning\033[0m");
}

TEST(Libcli2, DecoratorSupportsNamedColorThemes) {
    Context context;
    context.color_capable = true;
    context.color_mode = ColorMode::automatic;

    for (const auto name : color_theme_names) {
        ColorTheme parsed = ColorTheme::classic;
        ASSERT_TRUE(parse_color_theme(name, parsed));
        EXPECT_EQ(color_theme_name(parsed), name);
        context.color_theme = parsed;
        EXPECT_NE(context.decor().success("OK").find("\033["), std::string::npos);
        EXPECT_EQ(context.decor().error("FAIL").find(";4;"), std::string::npos);
    }

    ColorTheme parsed = ColorTheme::classic;
    EXPECT_FALSE(parse_color_theme("unknown", parsed));

    context.color_theme = ColorTheme::nord;
    EXPECT_EQ(context.decor().success("OK"), "\033[38;2;163;190;140mOK\033[0m");
    context.color_theme = ColorTheme::monokai;
    EXPECT_EQ(context.decor().error("FAIL"), "\033[1;38;2;249;38;114mFAIL\033[0m");
    context.color_theme = ColorTheme::matrix;
    EXPECT_EQ(context.decor().command("show"), "\033[38;2;65;255;99mshow\033[0m");
    context.color_theme = ColorTheme::amber;
    EXPECT_EQ(context.decor().muted("idle"), "\033[2;38;2;166;105;25midle\033[0m");
}

TEST(Libcli2, HelpUsesDecoratorsWithoutChangingPlainOutput) {
    Cli cli;
    cli.command("show session").help("List sessions").argument({"id", "Session id", false});
    Context context;

    const auto plain = cli.help("show session", context);
    EXPECT_EQ(plain.find("\033["), std::string::npos);

    context.color_mode = ColorMode::on;
    const auto colored = cli.help("show session", context);
    EXPECT_NE(colored.find("\033[36msession\033[0m"), std::string::npos);
    EXPECT_NE(colored.find("\033[2;37mList sessions\033[0m"), std::string::npos);
}

TEST(Libcli2, EveryColorThemeDecoratesEverySemanticStyle) {
    constexpr std::array styles {
        Style::heading, Style::command, Style::key, Style::value,
        Style::success, Style::warning, Style::error, Style::muted,
    };

    for (std::size_t theme_index = 0; theme_index < color_theme_names.size();
         ++theme_index) {
        auto const theme = static_cast<ColorTheme>(theme_index);
        ColorTheme parsed = ColorTheme::classic;
        ASSERT_TRUE(parse_color_theme(color_theme_name(theme), parsed));
        EXPECT_EQ(parsed, theme);

        Decorator decorator(true, theme);
        EXPECT_TRUE(decorator.enabled());
        for (auto const style : styles) {
            auto const rendered = decorator(style, "sample");
            EXPECT_NE(rendered.find("\033["), std::string::npos);
            EXPECT_NE(rendered.find("sample"), std::string::npos);
            EXPECT_EQ(rendered.substr(rendered.size() - 4), "\033[0m");
        }
        EXPECT_EQ(decorator(Style::plain, "sample"), "sample");
    }

    ColorTheme unchanged = ColorTheme::ice;
    EXPECT_FALSE(parse_color_theme("not-a-theme", unchanged));
    EXPECT_EQ(unchanged, ColorTheme::ice);
    Decorator disabled(false, ColorTheme::matrix);
    EXPECT_FALSE(disabled.enabled());
    EXPECT_EQ(disabled(Style::error, "sample"), "sample");
    EXPECT_EQ(Decorator(true, ColorTheme::classic)(Style::error, ""), "");
}

TEST(LineEditor, HistorySuppressesEmptyAndAdjacentDuplicatesAndRemainsBounded) {
    Cli cli;
    Context context;
    LineEditor editor(cli, context);

    editor.add_history("");
    editor.add_history("show status");
    editor.add_history("show status");
    for (int i = 0; i < 260; ++i)
        editor.add_history("command-" + std::to_string(i));

    auto const& history = LineEditorTestAccess::history(editor);
    ASSERT_EQ(history.size(), 256U);
    EXPECT_EQ(history.front(), "command-4");
    EXPECT_EQ(history.back(), "command-259");
}

TEST(LineEditor, AppliesUniqueAndCommonPrefixCompletions) {
    Cli cli;
    cli.command("show session").handler([](Context&, const Invocation&) { return 0; });
    cli.command("show settings").handler([](Context&, const Invocation&) { return 0; });
    Context context;
    LineEditor editor(cli, context);

    std::string command = "sh";
    std::size_t cursor = command.size();
    EXPECT_TRUE(LineEditorTestAccess::apply_completion(editor, command, cursor, false));
    EXPECT_EQ(command, "show ");
    EXPECT_EQ(cursor, command.size());

    command = "show s";
    cursor = command.size();
    EXPECT_TRUE(LineEditorTestAccess::apply_completion(editor, command, cursor, false));
    EXPECT_EQ(command, "show se");
    EXPECT_EQ(cursor, command.size());
}

TEST(LineEditor, ListsAmbiguousAndMissingCandidatesWithoutChangingInput) {
    Cli cli;
    cli.command("show session").help("Session details").handler(
        [](Context&, const Invocation&) { return 0; });
    cli.command("show settings").help("Configuration").handler(
        [](Context&, const Invocation&) { return 0; });
    Context context;
    LineEditor editor(cli, context);

    std::ostringstream output;
    ScopedStreamBuffer capture(std::cout, output.rdbuf());

    std::string command = "show se";
    std::size_t cursor = command.size();
    EXPECT_TRUE(LineEditorTestAccess::apply_completion(editor, command, cursor, true));
    EXPECT_EQ(command, "show se");
    EXPECT_NE(output.str().find("session"), std::string::npos);
    EXPECT_NE(output.str().find("settings"), std::string::npos);

    output.str({});
    output.clear();
    command = "unknown";
    cursor = command.size();
    EXPECT_FALSE(LineEditorTestAccess::apply_completion(editor, command, cursor, false));
    EXPECT_TRUE(LineEditorTestAccess::apply_completion(editor, command, cursor, true));
    EXPECT_NE(output.str().find("(no matches)"), std::string::npos);
}

TEST(LineEditor, RedrawRestoresCursorPosition) {
    Cli cli;
    Context context;
    LineEditor editor(cli, context);
    std::ostringstream output;
    ScopedStreamBuffer capture(std::cout, output.rdbuf());

    LineEditorTestAccess::redraw(editor, "# ", "status", 3);
    EXPECT_EQ(output.str(), "\r\033[2K# status\033[3D");
}

TEST(LineEditor, NonTerminalInputReturnsLinesAndCleanEof) {
    Cli cli;
    Context context;
    LineEditor editor(cli, context);
    std::istringstream input("show status\n\n");
    std::ostringstream output;
    ScopedInputBuffer replace_input(std::cin, input.rdbuf());
    ScopedStreamBuffer replace_output(std::cout, output.rdbuf());

    ASSERT_EQ(editor.read_line("first> "), std::optional<std::string>("show status"));
    ASSERT_EQ(editor.read_line("second> "), std::optional<std::string>(""));
    EXPECT_FALSE(editor.read_line("eof> ").has_value());
    EXPECT_EQ(LineEditorTestAccess::history(editor),
              (std::vector<std::string>{"show status"}));
    EXPECT_EQ(output.str(), "first> second> eof> ");
}

TEST(LineEditor, TerminalEditingCoversControlKeysHistoryCompletionAndEof) {
    Cli cli;
    cli.command("show session").help("Session details").handler(
        [](Context&, const Invocation&) { return 0; });
    cli.command("show settings").help("Configuration").handler(
        [](Context&, const Invocation&) { return 0; });
    Context context;
    LineEditor editor(cli, context);
    editor.add_history("history");
    std::ostringstream output;
    ScopedStreamBuffer replace_output(std::cout, output.rdbuf());

    auto edited = read_from_pseudoterminal(
        editor, "ab\x01X\033[C\033[D\x05\x7f\x15show s\t?\n");
    ASSERT_TRUE(edited.has_value());
    EXPECT_EQ(*edited, "show se");

    auto restored = read_from_pseudoterminal(
        editor, "draft\033[A\033[B\x04\n");
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(*restored, "draft");

    auto unknown = read_from_pseudoterminal(editor, "unknown?\n");
    ASSERT_TRUE(unknown.has_value());
    EXPECT_EQ(*unknown, "unknown");

    EXPECT_FALSE(read_from_pseudoterminal(editor, "\x04").has_value());
    EXPECT_NE(output.str().find("session"), std::string::npos);
    EXPECT_NE(output.str().find("(no matches)"), std::string::npos);
}

}  // namespace
}  // namespace libcli2
