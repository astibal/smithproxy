#include "config_cli2_schema.hpp"

#include <gtest/gtest.h>

using namespace smithproxy::config_cli;

namespace {

class NamedCollectionClassification : public testing::TestWithParam<const char*> {};
TEST_P(NamedCollectionClassification, IsNamedObjectCollection) {
    EXPECT_EQ(collection_kind(GetParam()), ConfigCollectionKind::named_objects);
}
INSTANTIATE_TEST_SUITE_P(AllSmithproxyNamedCollections, NamedCollectionClassification,
    testing::Values("proto_objects", "port_objects", "address_objects", "detection_profiles",
                    "content_profiles", "tls_ca", "tls_profiles", "alg_dns_profiles",
                    "auth_profiles", "routing"));

class OrderedCollectionClassification : public testing::TestWithParam<const char*> {};
TEST_P(OrderedCollectionClassification, IsOrderedObjectCollection) {
    EXPECT_EQ(collection_kind(GetParam()), ConfigCollectionKind::ordered_objects);
}
INSTANTIATE_TEST_SUITE_P(AllSmithproxyOrderedCollections, OrderedCollectionClassification,
    testing::Values("policy", "starttls_signatures", "detection_signatures",
                    "content_profiles.web.content_rules", "starttls_signatures.[0].flow",
                    "detection_signatures.[12].flow"));

class ValueArrayClassification : public testing::TestWithParam<const char*> {};
TEST_P(ValueArrayClassification, IsNeverAnObjectCollection) {
    EXPECT_EQ(collection_kind(GetParam()), ConfigCollectionKind::none);
}
INSTANTIATE_TEST_SUITE_P(AllKnownValueArrayShapes, ValueArrayClassification,
    testing::Values("settings.nameservers", "settings.udp_quick_ports", "settings.http_api.keys",
                    "settings.http_api.allowed_ips", "policy.[0].src", "policy.[0].sport",
                    "policy.[0].dst", "policy.[0].dport", "policy.[0].features",
                    "routing.default.dnat_address", "routing.default.dnat_port",
                    "tls_profiles.default.sni_filter_bypass",
                    "tls_profiles.default.redirect_warning_ports"));

TEST(ConfigCli2Schema, ClassifiesEverySupportedCollectionAndRejectsValueArrays) {
    EXPECT_EQ(collection_kind("address_objects"), ConfigCollectionKind::named_objects);
    EXPECT_EQ(collection_kind("routing"), ConfigCollectionKind::named_objects);
    EXPECT_EQ(collection_kind("policy"), ConfigCollectionKind::ordered_objects);
    EXPECT_EQ(collection_kind("detection_signatures"), ConfigCollectionKind::ordered_objects);
    EXPECT_EQ(collection_kind("content_profiles.web.content_rules"), ConfigCollectionKind::ordered_objects);
    EXPECT_EQ(collection_kind("detection_signatures.[2].flow"), ConfigCollectionKind::ordered_objects);
    EXPECT_EQ(collection_kind("policy.[0].src"), ConfigCollectionKind::none);
    EXPECT_EQ(collection_kind("settings.nameservers"), ConfigCollectionKind::none);
    EXPECT_EQ(collection_kind("tls_profiles.default.redirect_warning_ports"), ConfigCollectionKind::none);
}

TEST(ConfigCli2Schema, BuildsCompleteInertDetectionSignatureAndRejectsDuplicateAtomically) {
    libconfig::Config config;
    auto& list = config.getRoot().add("detection_signatures", libconfig::Setting::TypeList);
    std::string error;
    ASSERT_TRUE(add_ordered_entry(list, "detection_signatures", {"custom/http"}, error)) << error;
    ASSERT_EQ(list.getLength(), 1);
    EXPECT_EQ(static_cast<const char*>(list[0]["name"]), std::string("custom/http"));
    EXPECT_EQ(static_cast<const char*>(list[0]["cat"]), std::string("custom"));
    EXPECT_EQ(static_cast<const char*>(list[0]["side"]), std::string("client"));
    EXPECT_EQ(static_cast<const char*>(list[0]["group"]), std::string("base"));
    EXPECT_TRUE(list[0]["flow"].isList());
    EXPECT_EQ(list[0]["flow"].getLength(), 0);

    EXPECT_FALSE(add_ordered_entry(list, "detection_signatures", {"custom/http"}, error));
    EXPECT_EQ(list.getLength(), 1);
    EXPECT_NE(error.find("already exists"), std::string::npos);
}

TEST(ConfigCli2Schema, ValidatesSignatureNameBeforeMutation) {
    libconfig::Config config;
    auto& list = config.getRoot().add("starttls_signatures", libconfig::Setting::TypeList);
    std::string error;
    EXPECT_FALSE(add_ordered_entry(list, "starttls_signatures", {}, error));
    EXPECT_FALSE(add_ordered_entry(list, "starttls_signatures", {"__reserved"}, error));
    EXPECT_FALSE(add_ordered_entry(list, "starttls_signatures", {"one", "two"}, error));
    EXPECT_EQ(list.getLength(), 0);

    ASSERT_TRUE(add_ordered_entry(list, "starttls_signatures", {"smtp/custom"}, error));
    EXPECT_FALSE(list[0].exists("group"));
    EXPECT_TRUE(list[0]["flow"].isList());
}

TEST(ConfigCli2Schema, BuildsInertContentRuleAndRejectsUnexpectedName) {
    libconfig::Config config;
    auto& list = config.getRoot().add("rules", libconfig::Setting::TypeList);
    std::string error;
    const auto path = "content_profiles.web.content_rules";
    EXPECT_FALSE(add_ordered_entry(list, path, {"named"}, error));
    EXPECT_EQ(list.getLength(), 0);
    ASSERT_TRUE(add_ordered_entry(list, path, {}, error)) << error;
    EXPECT_EQ(static_cast<const char*>(list[0]["match"]), std::string("a^"));
    EXPECT_EQ(static_cast<const char*>(list[0]["replace"]), std::string(""));
}

TEST(ConfigCli2Schema, BuildsCompleteInertSignatureFlow) {
    libconfig::Config config;
    auto& list = config.getRoot().add("flow", libconfig::Setting::TypeList);
    std::string error;
    ASSERT_TRUE(add_ordered_entry(list, "detection_signatures.[0].flow", {}, error)) << error;
    ASSERT_EQ(list.getLength(), 1);
    EXPECT_EQ(static_cast<const char*>(list[0]["side"]), std::string("r"));
    EXPECT_EQ(static_cast<const char*>(list[0]["type"]), std::string("regex"));
    EXPECT_EQ(static_cast<const char*>(list[0]["signature"]), std::string("a^"));
    EXPECT_EQ(static_cast<int>(list[0]["bytes_start"]), 0);
    EXPECT_EQ(static_cast<int>(list[0]["bytes_max"]), 1);
}

TEST(ConfigCli2Schema, UnknownTemplateAndWrongContainerNeverMutate) {
    libconfig::Config config;
    auto& list = config.getRoot().add("unknown", libconfig::Setting::TypeList);
    auto& group = config.getRoot().add("group", libconfig::Setting::TypeGroup);
    std::string error;
    EXPECT_FALSE(add_ordered_entry(list, "unknown", {}, error));
    EXPECT_EQ(list.getLength(), 0);
    EXPECT_FALSE(add_ordered_entry(group, "content_profiles.web.content_rules", {}, error));
    EXPECT_EQ(group.getLength(), 0);
}

TEST(ConfigCli2Schema, PlansMultipleIndexesInSafeDescendingOrder) {
    libconfig::Config config;
    config.readString("items = ( {}, {}, {}, {} );");
    RemovePlan plan;
    std::string error;
    ASSERT_TRUE(plan_remove(config.lookup("items"), ConfigCollectionKind::ordered_objects,
                            {"[1]", "[3]"}, {}, plan, error)) << error;
    EXPECT_EQ(plan.indexes_descending, (std::vector<int>{3, 1}));
}

TEST(ConfigCli2Schema, RemovePlanRejectsWrongIdentityDuplicatesAndRange) {
    libconfig::Config config;
    config.readString("items = ( {}, {} ); objects = { one = {}; two = {}; }; ");
    RemovePlan plan;
    std::string error;
    EXPECT_FALSE(plan_remove(config.lookup("items"), ConfigCollectionKind::ordered_objects,
                             {"one"}, {}, plan, error));
    EXPECT_FALSE(plan_remove(config.lookup("objects"), ConfigCollectionKind::named_objects,
                             {"[0]"}, {}, plan, error));
    EXPECT_FALSE(plan_remove(config.lookup("items"), ConfigCollectionKind::ordered_objects,
                             {"[1]", "[1]"}, {}, plan, error));
    EXPECT_FALSE(plan_remove(config.lookup("items"), ConfigCollectionKind::ordered_objects,
                             {"[2]"}, {}, plan, error));
    EXPECT_FALSE(plan_remove(config.lookup("objects"), ConfigCollectionKind::named_objects,
                             {"missing"}, {}, plan, error));
}

class InvalidOrderedIndex : public testing::TestWithParam<const char*> {};
TEST_P(InvalidOrderedIndex, IsRejectedWithoutAPlan) {
    libconfig::Config config;
    config.readString("items = ( {}, {} );");
    RemovePlan plan;
    std::string error;
    EXPECT_FALSE(plan_remove(config.lookup("items"), ConfigCollectionKind::ordered_objects,
                             {GetParam()}, {}, plan, error));
}
INSTANTIATE_TEST_SUITE_P(MalformedAndOutOfRangeIndexes, InvalidOrderedIndex,
    testing::Values("0", "[]", "[-1]", "[+1]", "[ 1]", "[1 ]", "[x]", "[2]", "[999999]"));

TEST(ConfigCli2Schema, DependencyFailureAbortsWholeNamedRemovalPlan) {
    libconfig::Config config;
    config.readString("objects = { free = {}; used = {}; }; ");
    RemovePlan plan;
    std::string error;
    const UsageLookup usage = [](std::string_view name) {
        return name == "used" ? std::vector<std::string>{"policy.[2].src", "policy.[4].dst"}
                              : std::vector<std::string>{};
    };
    EXPECT_FALSE(plan_remove(config.lookup("objects"), ConfigCollectionKind::named_objects,
                             {"free", "used"}, usage, plan, error));
    EXPECT_NE(error.find("policy.[2].src"), std::string::npos);
    EXPECT_NE(error.find("policy.[4].dst"), std::string::npos);
    EXPECT_TRUE(config.exists("objects.free"));
    EXPECT_TRUE(config.exists("objects.used"));
}


}  // namespace
