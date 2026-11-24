#include <gtest/gtest.h>

#include <service/admin/admin_config_store.hpp>
#include <utils/crypto.hpp>

namespace {

class TestAdminArchive final : public sx::cfg::CfgArchiveStorage {
public:
    [[nodiscard]] bool available() const override { return source.has_value(); }
    [[nodiscard]] std::string current() const override { return source->archive_payload(); }
    [[nodiscard]] sx::cfg::CfgSaveData prepare_main(std::string) const override {
        throw std::logic_error("unused");
    }
    [[nodiscard]] sx::cfg::CfgSaveData prepare_resource(
        std::string path,
        std::optional<std::string> content,
        bool executable) const override {
        return source->prepare_resource(std::move(path), std::move(content), executable);
    }
    [[nodiscard]] bool publish(const sx::cfg::CfgSaveData& prepared) const override {
        ++writes;
        source->accept_saved_archive(prepared.replacement);
        return true;
    }
    [[nodiscard]] bool restart_required() const override { return restart_needed; }
    void require_restart() override { restart_needed = true; }

    mutable std::optional<sx::cfg::CfgArchive> source;
    mutable int writes = 0;
    bool restart_needed = false;
};

class AdminConfigStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        board.init_revision("running", "startup");
        sx::cfg::CfgTar tar;
        tar.add(std::string(sx::cfg::CfgManifest::path),
                sx::cfg::CfgManifest::canonical(sx::cfg::smithproxy_schema()));
        tar.add("smithproxy.cfg", "settings : {};\n");
        tar.add("smithproxy.startup.cfg", "START=1\n");
        archive.source = sx::cfg::CfgArchive::read_archive(
            sx::cfg::smithproxy_schema(), "smithproxy.cftar", tar.write());
    }

    std::string hash() const {
        return "sha256:" + *sx::crypto::sha256(archive.source->archive_payload());
    }

    sx::admin::ConfigStore store() {
        return sx::admin::ConfigStore({board, gate, mutex, archive});
    }

    void allow_another_write() { archive.restart_needed = false; }

    UpdateBoard board;
    sx::cfg::CfgWriteGate gate;
    std::recursive_mutex mutex;
    TestAdminArchive archive;
};

} // namespace

TEST_F(AdminConfigStoreTest, CreatesFirstAdministratorWithoutPersistingPlaintext) {
    const auto result = store().create(
        board.revision_current(), hash(), "alice", "correct horse battery staple");

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(archive.restart_needed);
    EXPECT_EQ(archive.writes, 1);
    const auto config = store().read();
    ASSERT_NE(config.find("alice"), nullptr);
    EXPECT_TRUE(config.find("alice")->enabled);
    EXPECT_TRUE(sx::crypto::password_matches(
        "correct horse battery staple", config.find("alice")->password_verifier));
    EXPECT_EQ(archive.source->archive().at("admin.cfg").data.find(
                  "correct horse battery staple"), std::string::npos);
}

TEST_F(AdminConfigStoreTest, RejectsDuplicateAdministratorWithoutPublishing) {
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "alice", "first password").ok());
    allow_another_write();

    const auto result = store().create(
        board.revision_current(), hash(), "alice", "second password");

    EXPECT_EQ(result.status, sx::admin::MutationStatus::already_exists);
    EXPECT_EQ(archive.writes, 1);
    const auto config = store().read();
    const auto* administrator = config.find("alice");
    ASSERT_NE(administrator, nullptr);
    EXPECT_TRUE(sx::crypto::password_matches("first password", administrator->password_verifier));
}

TEST_F(AdminConfigStoreTest, ChangesPasswordThroughTypedResourceMutation) {
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "alice", "first password").ok());
    allow_another_write();

    const auto result = store().change_password(
        board.revision_current(), hash(), "alice", "second password");

    ASSERT_TRUE(result.ok());
    const auto config = store().read();
    const auto* administrator = config.find("alice");
    ASSERT_NE(administrator, nullptr);
    EXPECT_FALSE(sx::crypto::password_matches("first password", administrator->password_verifier));
    EXPECT_TRUE(sx::crypto::password_matches("second password", administrator->password_verifier));
}

TEST_F(AdminConfigStoreTest, IdenticalStateChangeDoesNotPublishOrRequireRestart) {
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "alice", "password").ok());
    allow_another_write();

    const auto result = store().set_enabled(
        board.revision_current(), hash(), "alice", true);

    EXPECT_TRUE(result.ok());
    EXPECT_EQ(archive.writes, 1);
    EXPECT_FALSE(archive.restart_needed);
}

TEST_F(AdminConfigStoreTest, PreservesAtLeastOneEnabledAdministrator) {
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "alice", "alice password").ok());
    allow_another_write();
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "bob", "bob password").ok());
    allow_another_write();

    EXPECT_TRUE(store().set_enabled(board.revision_current(), hash(), "alice", false).ok());
    allow_another_write();
    const auto disable_last = store().set_enabled(
        board.revision_current(), hash(), "bob", false);
    const auto remove_last = store().remove(board.revision_current(), hash(), "bob");

    EXPECT_EQ(disable_last.status, sx::admin::MutationStatus::last_enabled_administrator);
    EXPECT_EQ(remove_last.status, sx::admin::MutationStatus::last_enabled_administrator);
    EXPECT_EQ(archive.writes, 3);
    const auto config = store().read();
    ASSERT_NE(config.find("bob"), nullptr);
    EXPECT_TRUE(config.find("bob")->enabled);
}

TEST_F(AdminConfigStoreTest, RemovesDisabledAndNonFinalAdministrators) {
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "alice", "alice password").ok());
    allow_another_write();
    ASSERT_TRUE(store().create(board.revision_current(), hash(), "bob", "bob password").ok());
    allow_another_write();
    ASSERT_TRUE(store().set_enabled(board.revision_current(), hash(), "bob", false).ok());
    allow_another_write();

    const auto result = store().remove(board.revision_current(), hash(), "bob");

    EXPECT_TRUE(result.ok());
    const auto config = store().read();
    EXPECT_EQ(config.find("bob"), nullptr);
    EXPECT_NE(config.find("alice"), nullptr);
}

TEST_F(AdminConfigStoreTest, RejectsInvalidInputsAndStaleArchiveGeneration) {
    EXPECT_EQ(store().create(board.revision_current(), hash(), "bad name", "password").status,
              sx::admin::MutationStatus::invalid_name);
    EXPECT_EQ(store().create(board.revision_current(), hash(), "alice", "").status,
              sx::admin::MutationStatus::invalid_password);

    const auto stale = store().create(
        board.revision_current(), "sha256:stale", "alice", "password");
    EXPECT_EQ(stale.status, sx::admin::MutationStatus::persistence_error);
    EXPECT_EQ(stale.persistence.status, sx::cfg::ResourceWriteStatus::hash_mismatch);
    EXPECT_EQ(archive.writes, 0);
}

TEST_F(AdminConfigStoreTest, RejectsChangesToUnknownAdministrator) {
    const auto password = store().change_password(
        board.revision_current(), hash(), "missing", "password");
    const auto enabled = store().set_enabled(
        board.revision_current(), hash(), "missing", false);
    const auto removed = store().remove(
        board.revision_current(), hash(), "missing");

    EXPECT_EQ(password.status, sx::admin::MutationStatus::not_found);
    EXPECT_EQ(enabled.status, sx::admin::MutationStatus::not_found);
    EXPECT_EQ(removed.status, sx::admin::MutationStatus::not_found);
    EXPECT_EQ(archive.writes, 0);
}

TEST_F(AdminConfigStoreTest, MalformedExistingAdminConfigFailsClosed) {
    const auto malformed = archive.source->prepare_resource(
        "admin.cfg", "admin = { schema_version = 99; administrators = (); };\n", false);
    archive.source->accept_saved_archive(malformed.replacement);

    const auto result = store().create(
        board.revision_current(), hash(), "alice", "password");

    EXPECT_EQ(result.status, sx::admin::MutationStatus::persistence_error);
    EXPECT_EQ(result.persistence.status, sx::cfg::ResourceWriteStatus::invalid_resource);
    EXPECT_EQ(archive.writes, 0);
    EXPECT_THROW({
        const auto ignored = store().read();
        (void)ignored;
    }, std::invalid_argument);
}
