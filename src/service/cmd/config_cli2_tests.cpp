#include "config_cli2.hpp"

#include <gtest/gtest.h>

#include <algorithm>

namespace {

class ConfigCli2Test : public testing::Test {
protected:
    void SetUp() override {
        config.readString(R"(
            settings = { cli = { port = 50000; }; };
            objects = {
                alpha = { value = "a"; };
                beta = { value = "b"; };
            };
            policy = (
                { name = "first"; proto = "tcp"; src = [ "any", "any6" ]; features = []; },
                { name = "second"; proto = "udp"; }
            );
            signatures = ();
        )");
        access.root = [&]() -> libconfig::Setting& { return config.getRoot(); };
        access.collection_kind = [](std::string_view path) {
            if (path == "policy" || path == "signatures") return ConfigCollectionKind::ordered_objects;
            if (path == "objects") return ConfigCollectionKind::named_objects;
            return ConfigCollectionKind::none;
        };
        access.can_add = [](std::string_view path) {
            return path == "policy" || path == "signatures" || path == "objects";
        };
        access.can_move = [](std::string_view path) { return path == "policy"; };
        access.values = [](std::string_view, std::string_view property) {
            if (property == "proto")
                return std::vector<libcli2::CompletionItem>{{"tcp", {}}, {"udp", {}}};
            return std::vector<libcli2::CompletionItem>{};
        };
        access.set = [&](std::string_view path, std::string_view property,
                         const std::vector<std::string>& values, std::string&) {
            last_values = values;
            last_set = std::string(path) + ":" + std::string(property) + "=" +
                       (values.empty() ? std::string{} : values.front());
            return true;
        };
        access.toggle = [&](std::string_view path, std::string_view property,
                            const std::vector<std::string>& values, std::string&) {
            last_set = std::string(path) + ":" + std::string(property);
            for (const auto& value : values) {
                const auto found = std::find(toggled_values.begin(), toggled_values.end(), value);
                if (found == toggled_values.end()) toggled_values.push_back(value);
                else toggled_values.erase(found);
            }
            return true;
        };
        access.add = [&](std::string_view path, const std::vector<std::string>& arguments, std::string& error) {
            auto& list = config.getRoot().lookup(std::string(path));
            if (path == "objects") {
                if (arguments.size() != 1 || list.exists(arguments[0])) { error = "invalid or duplicate name"; return false; }
                list.add(arguments[0], libconfig::Setting::TypeGroup)
                    .add("value", libconfig::Setting::TypeString) = "new";
                return true;
            }
            auto& added = list.add(libconfig::Setting::TypeGroup);
            added.add("name", libconfig::Setting::TypeString) = arguments.empty() ? "new" : arguments.front();
            added.add("proto", libconfig::Setting::TypeString) = "tcp";
            move_order.push_back(arguments.empty() ? "new" : arguments.front());
            return true;
        };
        access.remove = [&](std::string_view path, const std::vector<std::string>& entries, std::string& error) {
            auto& list = config.getRoot().lookup(std::string(path));
            if (path == "objects") {
                for (const auto& entry : entries)
                    if (!list.exists(entry)) { error = "unknown object"; return false; }
                for (const auto& entry : entries) list.remove(entry);
                return true;
            }
            std::vector<int> indexes;
            for (const auto& entry : entries) {
                if (entry.size() < 3 || entry.front() != '[' || entry.back() != ']') {
                    error = "invalid index";
                    return false;
                }
                const int index = std::stoi(entry.substr(1, entry.size() - 2));
                if (index < 0 || index >= list.getLength()) { error = "index out of range"; return false; }
                indexes.push_back(index);
            }
            std::sort(indexes.rbegin(), indexes.rend());
            for (const int index : indexes) list.remove(index);
            return true;
        };
        access.move = [&](std::string_view path, std::string_view source, std::string_view operation,
                          std::string_view target, std::string&) {
            last_move = std::string(path) + ":" + std::string(source) + ":" + std::string(operation) +
                        ":" + std::string(target);
            auto index = [](std::string_view value) { return std::stoi(std::string(value.substr(1, value.size() - 2))); };
            const int from = index(source);
            if (from < 0 || from >= static_cast<int>(move_order.size())) return false;
            int destination = from;
            if (operation == "top") destination = 0;
            else if (operation == "bottom") destination = static_cast<int>(move_order.size()) - 1;
            else if (operation == "up") destination = from - 1;
            else if (operation == "down") destination = from + 1;
            else {
                destination = index(target);
                if (from < destination) --destination;
                if (operation == "after") ++destination;
            }
            if (destination < 0 || destination >= static_cast<int>(move_order.size())) return false;
            auto value = move_order[from];
            move_order.erase(move_order.begin() + from);
            move_order.insert(move_order.begin() + destination, std::move(value));
            return true;
        };
        move_order = {"first", "second"};
        toggled_values = {"one", "keep"};
        state.reset(new ConfigCli2Session(access));
        context.user_data = state.get();
        state->register_commands(cli);
    }

    libconfig::Config config;
    ConfigCli2Access access;
    std::unique_ptr<ConfigCli2Session> state;
    libcli2::Cli cli;
    libcli2::Context context;
    std::string last_set;
    std::string last_move;
    std::vector<std::string> last_values;
    std::vector<std::string> toggled_values;
    std::vector<std::string> move_order;
};

class ConfigCommandBeforeMode : public ConfigCli2Test, public testing::WithParamInterface<const char*> {};
TEST_P(ConfigCommandBeforeMode, IsUnavailableBeforeConfigureTerminal) {
    EXPECT_FALSE(cli.execute(GetParam(), context));
}
INSTANTIATE_TEST_SUITE_P(AllConfigOnlyCommands, ConfigCommandBeforeMode,
    testing::Values("edit policy", "set proto tcp", "toggle tags one", "add entry",
                    "remove [0]", "move [0] top", "where", "end"));

TEST_F(ConfigCli2Test, NavigatesLiveConfigurationWithoutNumericModes) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    auto root = cli.complete("edit p", context);
    ASSERT_EQ(root.items.size(), 1U);
    EXPECT_EQ(root.items.front().value, "policy");

    ASSERT_TRUE(cli.execute("edit policy [1]", context));
    EXPECT_EQ(state->path(), "policy.[1]");
    ASSERT_TRUE(cli.execute("set proto tcp", context));
    EXPECT_EQ(last_set, "policy.[1]:proto=tcp");
}

TEST_F(ConfigCli2Test, CompletionReadsCurrentNodeAndPreviousArgument) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy [0]", context));

    auto properties = cli.complete("set pr", context);
    ASSERT_EQ(properties.items.size(), 1U);
    EXPECT_EQ(properties.items.front().value, "proto");

    auto values = cli.complete("set proto u", context);
    ASSERT_EQ(values.items.size(), 1U);
    EXPECT_EQ(values.items.front().value, "udp");
}

TEST_F(ConfigCli2Test, SetForwardsAllValuesIncludingQuotedTokens) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy [0]", context));
    ASSERT_TRUE(cli.execute("set proto tcp 'two words' udp", context));
    EXPECT_EQ(last_values, (std::vector<std::string>{"tcp", "two words", "udp"}));
}

TEST_F(ConfigCli2Test, EndWalksBackThenLeavesConfigurationMode) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit settings cli", context));
    ASSERT_TRUE(state->active());

    ASSERT_TRUE(cli.execute("end", context));
    EXPECT_TRUE(state->active());
    EXPECT_TRUE(state->path().empty());
    ASSERT_TRUE(cli.execute("end", context));
    EXPECT_FALSE(state->active());
}

TEST_F(ConfigCli2Test, ConfigureCannotBeEnteredTwiceAndResetReturnsToExecCommands) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    EXPECT_FALSE(cli.execute("configure terminal", context));
    state->reset();
    EXPECT_FALSE(state->active());
    EXPECT_TRUE(cli.execute("configure terminal", context));
}

TEST_F(ConfigCli2Test, InvalidEditIsAtomicAndReportsAnError) {
    std::vector<std::string> output;
    context.write = [&](std::string_view value) { output.emplace_back(value); };
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    EXPECT_FALSE(cli.execute("edit [99]", context));
    EXPECT_EQ(state->path(), "policy");
    ASSERT_FALSE(output.empty());
    EXPECT_EQ(output.back(), "unknown configuration section");
}

TEST_F(ConfigCli2Test, ValueArraysArePropertiesAndCannotBeEnteredAsSections) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy [0]", context));

    const auto completion = cli.complete("edit ", context);
    EXPECT_TRUE(std::none_of(completion.items.begin(), completion.items.end(),
                             [](const auto& item) { return item.value == "src" || item.value == "features"; }));
    EXPECT_FALSE(cli.execute("edit src", context));
    EXPECT_FALSE(cli.execute("edit features", context));
    EXPECT_EQ(state->path(), "policy.[0]");
}

TEST_F(ConfigCli2Test, SetToggleAndRemoveEnforceRequiredArguments) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy [0]", context));
    EXPECT_FALSE(cli.execute("set", context));
    EXPECT_FALSE(cli.execute("set proto", context));
    EXPECT_FALSE(cli.execute("toggle", context));
    EXPECT_FALSE(cli.execute("toggle tags", context));
    ASSERT_TRUE(cli.execute("end", context));
    EXPECT_FALSE(cli.execute("remove", context));
}

TEST_F(ConfigCli2Test, WherePrintsRootAndNestedCanonicalPaths) {
    std::vector<std::string> output;
    context.write = [&](std::string_view value) { output.emplace_back(value); };
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("where", context));
    EXPECT_EQ(output.back(), "/");
    ASSERT_TRUE(cli.execute("edit policy [1]", context));
    ASSERT_TRUE(cli.execute("where", context));
    EXPECT_EQ(output.back(), "policy.[1]");
}

TEST_F(ConfigCli2Test, AddAndRemoveAreImmediatelyVisibleToCompletion) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    ASSERT_TRUE(cli.execute("add third", context));

    auto after_add = cli.complete("edit [", context);
    ASSERT_EQ(after_add.items.size(), 3U);
    EXPECT_EQ(after_add.items.back().value, "[2]");

    ASSERT_TRUE(cli.execute("remove [2]", context));
    auto after_remove = cli.complete("edit [", context);
    ASSERT_EQ(after_remove.items.size(), 2U);
}

TEST_F(ConfigCli2Test, ToggleAndMoveUseTypedDynamicArguments) {
    auto& first = config.getRoot().lookup("policy.[0]");
    first.add("tags", libconfig::Setting::TypeArray).add(libconfig::Setting::TypeString) = "one";
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy [0]", context));
    EXPECT_TRUE(cli.execute("toggle tags two", context));
    EXPECT_EQ(last_set, "policy.[0]:tags");
    EXPECT_EQ(toggled_values, (std::vector<std::string>{"one", "keep", "two"}));
    EXPECT_TRUE(cli.execute("toggle tags one two", context));
    EXPECT_EQ(toggled_values, (std::vector<std::string>{"keep"}));
    ASSERT_TRUE(cli.execute("end", context));
    ASSERT_TRUE(cli.execute("edit policy", context));

    ASSERT_TRUE(cli.execute("move [0] after [1]", context));
    EXPECT_EQ(last_move, "policy:[0]:after:[1]");
}

TEST_F(ConfigCli2Test, NamedObjectAddRemoveAndCompletionAreLive) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit objects", context));
    ASSERT_TRUE(cli.execute("add gamma", context));
    EXPECT_TRUE(config.exists("objects.gamma"));
    ASSERT_EQ(cli.complete("edit g", context).items.size(), 1U);
    EXPECT_FALSE(cli.execute("add gamma", context));
    EXPECT_TRUE(config.exists("objects.gamma"));
    ASSERT_TRUE(cli.execute("remove alpha gamma", context));
    EXPECT_FALSE(config.exists("objects.alpha"));
    EXPECT_FALSE(config.exists("objects.gamma"));
    EXPECT_TRUE(config.exists("objects.beta"));
}

TEST_F(ConfigCli2Test, MultipleIndexedRemoveUsesOriginalIndexesAndIsAtomicOnError) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    ASSERT_TRUE(cli.execute("add third", context));
    ASSERT_TRUE(cli.execute("add fourth", context));
    ASSERT_TRUE(cli.execute("remove [1] [3]", context));
    auto& policy = config.lookup("policy");
    ASSERT_EQ(policy.getLength(), 2);
    EXPECT_EQ(static_cast<const char*>(policy[0]["name"]), std::string("first"));
    EXPECT_EQ(static_cast<const char*>(policy[1]["name"]), std::string("third"));

    EXPECT_FALSE(cli.execute("remove [0] [9]", context));
    EXPECT_EQ(policy.getLength(), 2);
    EXPECT_EQ(static_cast<const char*>(policy[0]["name"]), std::string("first"));
}

TEST_F(ConfigCli2Test, MoveSupportsEveryOperationAndActuallyChangesOrder) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    ASSERT_TRUE(cli.execute("add third", context));
    ASSERT_TRUE(cli.execute("add fourth", context));

    ASSERT_TRUE(cli.execute("move [3] top", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"fourth", "first", "second", "third"}));
    ASSERT_TRUE(cli.execute("move [0] bottom", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "second", "third", "fourth"}));
    ASSERT_TRUE(cli.execute("move [2] up", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "third", "second", "fourth"}));
    ASSERT_TRUE(cli.execute("move [1] down", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "second", "third", "fourth"}));
    ASSERT_TRUE(cli.execute("move [3] before [1]", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "fourth", "second", "third"}));
    ASSERT_TRUE(cli.execute("move [1] after [3]", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "second", "third", "fourth"}));
}

TEST_F(ConfigCli2Test, MoveRejectsMissingOrUnexpectedTargetBeforeBackendMutation) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    EXPECT_FALSE(cli.execute("move [0] before", context));
    EXPECT_FALSE(cli.execute("move [0] top [1]", context));
    EXPECT_EQ(move_order, (std::vector<std::string>{"first", "second"}));
}

TEST_F(ConfigCli2Test, RemoveAndMoveAreHiddenOutsideObjectCollections) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit settings cli", context));
    EXPECT_FALSE(cli.execute("remove port", context));
    EXPECT_FALSE(cli.execute("move [0] top", context));
}

TEST_F(ConfigCli2Test, IndexedEntryCompletionShowsItsSemanticName) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit policy", context));
    const auto result = cli.complete("edit [0", context);
    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items[0].value, "[0]");
    EXPECT_EQ(result.items[0].description, "first");
}

TEST_F(ConfigCli2Test, AddIsAvailableForAnotherExplicitOrderedCollection) {
    ASSERT_TRUE(cli.execute("configure terminal", context));
    ASSERT_TRUE(cli.execute("edit signatures", context));
    ASSERT_TRUE(cli.execute("add named-signature", context));
    const auto result = cli.complete("edit [", context);
    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items[0].description, "named-signature");
}

}  // namespace
