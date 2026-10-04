#include <gtest/gtest.h>

#include <service/core/authpam.hpp>

#ifdef USE_PAM

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

TEST(PamAuth, RejectsNullCredentialsWithoutEnteringPam) {
    EXPECT_FALSE(sx::auth::pam_auth_user_pass(nullptr, "password"));
    EXPECT_FALSE(sx::auth::pam_auth_user_pass("user", nullptr));
    EXPECT_FALSE(sx::auth::pam_auth_user_pass("", "password"));
}

TEST(PamAuth, GroupLookupRejectsMissingAndNullIdentities) {
    EXPECT_FALSE(sx::auth::unix_is_group_member(nullptr, "group"));
    EXPECT_FALSE(sx::auth::unix_is_group_member("user", nullptr));
    EXPECT_FALSE(sx::auth::unix_is_group_member("smithproxy-user-that-does-not-exist",
                                                "smithproxy-group-that-does-not-exist"));
}

TEST(PamAuth, GroupLookupFindsTheCurrentUsersPrimaryGroup) {
    auto const* user = getpwuid(getuid());
    ASSERT_NE(user, nullptr);
    auto const* group = getgrgid(user->pw_gid);
    ASSERT_NE(group, nullptr);
    EXPECT_TRUE(sx::auth::unix_is_group_member(user->pw_name, group->gr_name));
}

#endif
