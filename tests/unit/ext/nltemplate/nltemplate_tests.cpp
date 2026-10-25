#include <gtest/gtest.h>

#include <ext/nltemplate/nltemplate.hpp>

using namespace ext::nltemplate;

TEST(NlTemplate, RendersVariablesIncludesAndRepeatedBlocks) {
    LoaderMemory loader;
    loader.add("included", "included={{ value }}");
    loader.add("main", "head {% include included %} {% block row %}[{{ item }}]{% endblock %}");
    Template value(loader);
    value.load("main");
    value.set("value", "ok");
    auto& row = value.block("row");
    row.repeat(2);
    row[0].set("item", "a");
    row[1].set("item", "b");

    EXPECT_EQ(value.render(), "head included=ok [a][b]");
    row.disable();
    EXPECT_EQ(value.render(), "head included=ok ");
    row.enable();
}

TEST(NlTemplate, RejectsMissingAndMalformedTemplates) {
    LoaderMemory loader;
    Template value(loader);
    EXPECT_THROW(value.load("missing"), std::runtime_error);

    loader.add("unmatched", "{% endblock %}");
    EXPECT_THROW(value.load("unmatched"), std::runtime_error);
    loader.add("unclosed", "{% block row %}body");
    EXPECT_THROW(value.load("unclosed"), std::runtime_error);

    int index = 0;
    for (std::string const truncated : {"{", "{{", "{{ ", "{%", "{% ", "{% block"}) {
        const auto name = "truncated-" + std::to_string(index++);
        loader.add(name, truncated);
        EXPECT_NO_THROW(value.load(name));
        EXPECT_EQ(value.render(), truncated);
    }
}

TEST(NlTemplate, BoundsRecursiveIncludes) {
    LoaderMemory loader;
    loader.add("loop", "{% include loop %}");
    Template value(loader);
    EXPECT_THROW(value.load("loop"), std::runtime_error);
}
