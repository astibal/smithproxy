#include "cli.hpp"

#include <gtest/gtest.h>

namespace libcli2 {
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

}  // namespace
}  // namespace libcli2
