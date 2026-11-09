#include <gtest/gtest.h>

#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_archive_session.hpp>
#include <service/cfgapi/cfg_exposure.hpp>
#include <service/cfgapi/cfg_file_lock.hpp>
#include <service/cfgapi/cfg_io.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

using sx::cfg::CfgArchiveSession;
using sx::cfg::CfgExposureRegistry;
using sx::cfg::CfgFileLock;
using sx::cfg::CfgIo;
using sx::cfg::CfgManifest;
using sx::cfg::CfgTar;
using sx::cfg::CfgTarError;

// Injects one selected POSIX outcome while every other operation continues to
// use the production implementation. The call index distinguishes repeated
// phases such as recovery publication and active-archive publication.
class FaultCfgIo : public CfgIo {
public:
    enum class At {
        open_read,
        open_lock,
        lock_error,
        inspect_open,
        read_error,
        read_eintr,
        read_eof,
        close,
        inspect_path,
        create_temp,
        set_mode,
        set_owner,
        write_error,
        write_eintr,
        write_zero,
        write_short,
        sync,
        replace,
        open_directory,
    };

    explicit FaultCfgIo(At at, std::size_t call = 1)
        : at_(at), target_call_(call) {}

    int open_read(const std::string& path) const override {
        if(hit(At::open_read)) return fail_int();
        return CfgIo::open_read(path);
    }

    int open_lock(const std::string& path) const override {
        if(hit(At::open_lock)) return fail_int();
        return CfgIo::open_lock(path);
    }

    int lock(int fd, int operation) const override {
        if(hit(At::lock_error)) return fail_int(EBADF);
        return CfgIo::lock(fd, operation);
    }

    int inspect_open(int fd, struct stat* metadata) const override {
        if(hit(At::inspect_open)) return fail_int();
        return CfgIo::inspect_open(fd, metadata);
    }

    ssize_t read(int fd, void* buffer, std::size_t size) const override {
        if(hit(At::read_error)) return fail_size(EIO);
        if(hit(At::read_eintr)) return fail_size(EINTR);
        if(hit(At::read_eof)) return 0;
        return CfgIo::read(fd, buffer, size);
    }

    int close(int fd) const override {
        const auto result = CfgIo::close(fd);
        if(hit(At::close)) return fail_int();
        return result;
    }

    int inspect_path(const std::string& path, struct stat* metadata) const override {
        if(hit(At::inspect_path)) return fail_int(EACCES);
        return CfgIo::inspect_path(path, metadata);
    }

    int create_temp(std::string& pattern) const override {
        if(hit(At::create_temp)) return fail_int();
        return CfgIo::create_temp(pattern);
    }

    int set_mode(int fd, mode_t mode) const override {
        if(hit(At::set_mode)) return fail_int();
        return CfgIo::set_mode(fd, mode);
    }

    int set_owner(int fd, uid_t owner, gid_t group) const override {
        if(hit(At::set_owner)) return fail_int();
        return CfgIo::set_owner(fd, owner, group);
    }

    ssize_t write(int fd, const void* buffer, std::size_t size) const override {
        if(hit(At::write_error)) return fail_size(EIO);
        if(hit(At::write_eintr)) return fail_size(EINTR);
        if(hit(At::write_zero)) return 0;
        if(hit(At::write_short)) {
            return CfgIo::write(fd, buffer, std::min<std::size_t>(size, 7));
        }
        return CfgIo::write(fd, buffer, size);
    }

    int sync(int fd) const override {
        if(hit(At::sync)) return fail_int();
        return CfgIo::sync(fd);
    }

    int replace(const std::string& from, const std::string& to) const override {
        if(hit(At::replace)) return fail_int();
        return CfgIo::replace(from, to);
    }

    int open_directory(const std::string& path) const override {
        if(hit(At::open_directory)) return fail_int();
        return CfgIo::open_directory(path);
    }

private:
    bool hit(At operation) const {
        if(operation != at_) return false;
        return ++calls_ == target_call_;
    }

    static int fail_int(int error = EIO) {
        errno = error;
        return -1;
    }

    static ssize_t fail_size(int error) {
        errno = error;
        return -1;
    }

    At at_;
    std::size_t target_call_;
    mutable std::size_t calls_ = 0;
};

// Turns a successful syscall into a deliberately slow one. This models a busy
// device without changing its result, allowing timeout and serialization tests
// to distinguish latency from an actual storage failure.
class SlowCfgIo : public CfgIo {
public:
    enum class At {
        read,
        write,
        sync,
    };

    SlowCfgIo(
        At at,
        std::chrono::milliseconds delay,
        std::size_t maximum_pauses = std::numeric_limits<std::size_t>::max())
        : at_(at), delay_(delay), maximum_pauses_(maximum_pauses) {}

    ssize_t read(int fd, void* buffer, std::size_t size) const override {
        pause(At::read);
        return CfgIo::read(fd, buffer, size);
    }

    ssize_t write(int fd, const void* buffer, std::size_t size) const override {
        pause(At::write);
        return CfgIo::write(fd, buffer, size);
    }

    int sync(int fd) const override {
        pause(At::sync);
        return CfgIo::sync(fd);
    }

    bool wait_until_entered(std::chrono::milliseconds timeout) const {
        std::unique_lock lock(mutex_);
        return entered_.wait_for(lock, timeout, [this] { return entered_io_; });
    }

private:
    void pause(At operation) const {
        if(operation != at_) return;
        {
            std::lock_guard lock(mutex_);
            if(pause_count_ >= maximum_pauses_) return;
            ++pause_count_;
            entered_io_ = true;
        }
        entered_.notify_all();
        std::this_thread::sleep_for(delay_);
    }

    At at_;
    std::chrono::milliseconds delay_;
    std::size_t maximum_pauses_;
    mutable std::mutex mutex_;
    mutable std::condition_variable entered_;
    mutable bool entered_io_ = false;
    mutable std::size_t pause_count_ = 0;
};

// Performs one deliberately hostile filesystem mutation from inside a normal
// publication syscall. This closes timing races deterministically without
// adding sleeps or test switches to production code.
class MutatingCfgIo : public CfgIo {
public:
    enum class Action {
        remove_recovery_after_replace,
        corrupt_recovery_after_replace,
        remove_temporary_during_write,
    };

    explicit MutatingCfgIo(Action action)
        : action_(action) {}

    int create_temp(std::string& pattern) const override {
        const auto result = CfgIo::create_temp(pattern);
        if(result >= 0) temporary_path_ = pattern;
        return result;
    }

    ssize_t write(int fd, const void* buffer, std::size_t size) const override {
        if(action_ == Action::remove_temporary_during_write && !mutated_) {
            mutated_ = true;
            if(!temporary_path_.empty()) ::unlink(temporary_path_.c_str());
        }
        return CfgIo::write(fd, buffer, size);
    }

    int replace(const std::string& from, const std::string& to) const override {
        const auto result = CfgIo::replace(from, to);
        static const std::string recovery_suffix = ".previous.bak.cftar";
        const bool is_recovery =
            to.size() >= recovery_suffix.size() &&
            to.compare(
                to.size() - recovery_suffix.size(),
                recovery_suffix.size(),
                recovery_suffix) == 0;
        if(result == 0 && is_recovery && !mutated_ &&
           action_ == Action::remove_recovery_after_replace) {
            mutated_ = true;
            ::unlink(to.c_str());
        }
        if(result == 0 && is_recovery && !mutated_ &&
           action_ == Action::corrupt_recovery_after_replace) {
            mutated_ = true;
            std::ofstream replacement(to, std::ios::binary | std::ios::trunc);
            replacement << "external recovery replacement";
        }
        return result;
    }

private:
    Action action_;
    mutable bool mutated_ = false;
    mutable std::string temporary_path_;
};

// Stops a child process at one exact publication boundary so the parent can
// deliver SIGKILL and inspect the filesystem state left by kernel cleanup.
class KillPointCfgIo : public CfgIo {
public:
    enum class After {
        directory_lock,
        recovery_replace,
        active_replace,
    };

    KillPointCfgIo(After after, std::string archive_path, int ready_fd)
        : after_(after),
          archive_path_(std::move(archive_path)),
          ready_fd_(ready_fd) {}

    int lock(int fd, int operation) const override {
        const auto result = CfgIo::lock(fd, operation);
        if(result == 0 &&
           after_ == After::directory_lock &&
           (operation & LOCK_EX) != 0) {
            stop_here();
        }
        return result;
    }

    int replace(const std::string& from, const std::string& to) const override {
        const auto result = CfgIo::replace(from, to);
        if(result != 0) return result;
        if(after_ == After::recovery_replace &&
           to == archive_path_ + ".previous.bak.cftar") {
            stop_here();
        }
        if(after_ == After::active_replace && to == archive_path_) {
            stop_here();
        }
        return result;
    }

private:
    [[noreturn]] void stop_here() const {
        const char ready = '1';
        if(::write(ready_fd_, &ready, 1) != 1) _exit(90);
        for(;;) ::pause();
    }

    After after_;
    std::string archive_path_;
    int ready_fd_;
};

// Returns one real resource-exhaustion errno at a selected publication call.
// An optional delay models a busy device that fails only after holding the
// inter-process lock for a meaningful amount of time.
class ResourceFailureCfgIo : public CfgIo {
public:
    enum class At {
        open_directory,
        create_temp,
        write,
        sync,
    };

    ResourceFailureCfgIo(
        At at,
        int error,
        std::size_t target_call = 1,
        std::chrono::milliseconds delay = std::chrono::milliseconds::zero())
        : at_(at),
          error_(error),
          target_call_(target_call),
          delay_(delay) {}

    int open_directory(const std::string& path) const override {
        if(hit(At::open_directory)) return fail_int();
        return CfgIo::open_directory(path);
    }

    int create_temp(std::string& pattern) const override {
        if(hit(At::create_temp)) return fail_int();
        return CfgIo::create_temp(pattern);
    }

    ssize_t write(int fd, const void* buffer, std::size_t size) const override {
        if(hit(At::write)) return fail_size();
        return CfgIo::write(fd, buffer, size);
    }

    int sync(int fd) const override {
        if(hit(At::sync)) return fail_int();
        return CfgIo::sync(fd);
    }

    bool wait_until_entered(std::chrono::milliseconds timeout) const {
        std::unique_lock lock(mutex_);
        return entered_.wait_for(lock, timeout, [this] { return entered_failure_; });
    }

private:
    bool hit(At operation) const {
        if(operation != at_ || ++calls_ != target_call_) return false;
        {
            std::lock_guard lock(mutex_);
            entered_failure_ = true;
        }
        entered_.notify_all();
        if(delay_ > std::chrono::milliseconds::zero()) {
            std::this_thread::sleep_for(delay_);
        }
        return true;
    }

    int fail_int() const {
        errno = error_;
        return -1;
    }

    ssize_t fail_size() const {
        errno = error_;
        return -1;
    }

    At at_;
    int error_;
    std::size_t target_call_;
    std::chrono::milliseconds delay_;
    mutable std::size_t calls_ = 0;
    mutable std::mutex mutex_;
    mutable std::condition_variable entered_;
    mutable bool entered_failure_ = false;
};

class ArchiveSessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string pattern = "/tmp/smithproxy-cftar-session-test-XXXXXX";
        directory_ = ::mkdtemp(pattern.data());
        ASSERT_FALSE(directory_.empty());
        archive_path_ = directory_ + "/smithproxy.cftar";
        write_archive(valid_archive());
    }

    void TearDown() override {
        std::filesystem::remove_all(directory_);
    }

    CfgTar valid_archive() const {
        CfgTar archive;
        archive.add(std::string(CfgManifest::path), CfgManifest::canonical());
        archive.add("smithproxy.cfg", "settings : {};\n");
        archive.add("smithproxy.startup.cfg", "SMITH_RUN_TRANSPARENT=1\n");
        archive.add("templates/replacement/en/page.html", "original");
        return archive;
    }

    void write_archive(const CfgTar& archive) const {
        archive.write_file(archive_path_);
    }

    std::string directory_;
    std::string archive_path_;
};

TEST_F(ArchiveSessionTest, OpensValidatedArchiveAsCleanWorkingCopy) {
    const auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("templates/replacement/en/page.html").data, "original");
    EXPECT_EQ(session.base_hash().find("sha256:"), 0U);
}

TEST_F(ArchiveSessionTest, RejectsMissingDirectoryAndOversizedArchiveInputs) {
    EXPECT_THROW(CfgArchiveSession::open(directory_ + "/missing.cftar"), CfgTarError);
    EXPECT_THROW(CfgArchiveSession::open(directory_), CfgTarError);

    const auto oversized = directory_ + "/oversized.cftar";
    const int fd = ::open(oversized.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::ftruncate(fd, 256LL * 1024LL * 1024LL + 1), 0);
    ASSERT_EQ(::close(fd), 0);
    EXPECT_THROW(CfgArchiveSession::open(oversized), CfgTarError);
}

TEST_F(ArchiveSessionTest, ReportsInjectedArchiveReadFailures) {
    using At = FaultCfgIo::At;
    for(const auto failure : {At::open_read, At::inspect_open, At::read_error,
                              At::read_eof, At::close}) {
        SCOPED_TRACE(static_cast<int>(failure));
        EXPECT_THROW(
            CfgArchiveSession::open(
                archive_path_, std::make_shared<FaultCfgIo>(failure)),
            CfgTarError);
    }
}

TEST_F(ArchiveSessionTest, RetriesInterruptedReads) {
    auto session = CfgArchiveSession::open(
        archive_path_, std::make_shared<FaultCfgIo>(FaultCfgIo::At::read_eintr));

    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("templates/replacement/en/page.html").data, "original");
}

TEST_F(ArchiveSessionTest, SlowReadCompletesWithoutBecomingAnIoFailure) {
    const auto delay = std::chrono::milliseconds(60);
    const auto io = std::make_shared<SlowCfgIo>(SlowCfgIo::At::read, delay);
    const auto started = std::chrono::steady_clock::now();

    const auto session = CfgArchiveSession::open(archive_path_, io);

    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, delay);
    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("templates/replacement/en/page.html").data, "original");
}

TEST_F(ArchiveSessionTest, RejectsMissingIoProvider) {
    EXPECT_THROW(CfgArchiveSession::open(archive_path_, nullptr), CfgTarError);
}

TEST_F(ArchiveSessionTest, StagesAndDiscardsResourceChanges) {
    auto session = CfgArchiveSession::open(archive_path_);

    session.put("templates/replacement/en/page.html", "changed");
    session.put("commands/scripts/inspect.macro", "show config");
    EXPECT_TRUE(session.dirty());
    ASSERT_EQ(session.changes().size(), 2U);

    session.discard();
    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("templates/replacement/en/page.html").data, "original");
    EXPECT_FALSE(session.archive().contains("commands/scripts/inspect.macro"));
}

TEST_F(ArchiveSessionTest, RejectsInvalidMainConfigurationBeforeStaging) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.put("smithproxy.cfg", "settings : {"), CfgTarError);
    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(session.entry("smithproxy.cfg").data, "settings : {};\n");
}

TEST_F(ArchiveSessionTest, RejectsRemovingControlFiles) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.remove("smithproxy.cfg"), CfgTarError);
    EXPECT_THROW(session.remove(CfgManifest::path), CfgTarError);
    EXPECT_FALSE(session.dirty());
}

TEST_F(ArchiveSessionTest, KeepsManifestUnderFormatControl) {
    auto session = CfgArchiveSession::open(archive_path_);

    EXPECT_THROW(session.put(
                     std::string(CfgManifest::path), CfgManifest::canonical()),
                 CfgTarError);
    EXPECT_FALSE(session.dirty());
}

TEST_F(ArchiveSessionTest, SavesRecoveryCopyBeforeAtomicReplacement) {
    auto session = CfgArchiveSession::open(archive_path_);
    session.put("templates/replacement/en/page.html", "changed");

    session.save();

    EXPECT_FALSE(session.dirty());
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("templates/replacement/en/page.html").data,
              "changed");
    EXPECT_EQ(CfgTar::read_file(archive_path_ + ".previous.bak.cftar")
                  .at("templates/replacement/en/page.html").data,
              "original");
}

TEST_F(ArchiveSessionTest, FailedRecoveryPublicationPreservesActiveArchive) {
    auto session = CfgArchiveSession::open(archive_path_);
    session.put("templates/replacement/en/page.html", "changed");
    const auto recovery = archive_path_ + ".previous.bak.cftar";
    ASSERT_TRUE(std::filesystem::create_directory(recovery));

    EXPECT_THROW(session.save(), CfgTarError);

    EXPECT_TRUE(session.dirty());
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("templates/replacement/en/page.html").data,
              "original");
    EXPECT_TRUE(std::filesystem::is_directory(recovery));
}

TEST_F(ArchiveSessionTest, InjectedRecoveryFailuresPreserveActiveArchive) {
    using At = FaultCfgIo::At;
    for(const auto failure : {At::inspect_path, At::create_temp, At::set_mode,
                              At::write_error, At::write_zero, At::sync,
                              At::close, At::replace, At::open_directory}) {
        SCOPED_TRACE(static_cast<int>(failure));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");

        // close #1 opened the session, #2 rechecked the current generation,
        // and #3 belongs to the recovery temporary file under test.
        const auto call = failure == At::close ? 3U : 1U;
        auto session = CfgArchiveSession::open(
            archive_path_, std::make_shared<FaultCfgIo>(failure, call));
        session.put("templates/replacement/en/page.html", "changed");

        EXPECT_THROW(session.save(), CfgTarError);
        EXPECT_TRUE(session.dirty());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "original");
    }
}

TEST_F(ArchiveSessionTest, ReportsRecoveryDirectoryDurabilityFailures) {
    using At = FaultCfgIo::At;
    for(const auto [failure, call] : {
            std::pair{At::sync, 2U},
            std::pair{At::close, 4U}}) {
        SCOPED_TRACE(static_cast<int>(failure));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        auto session = CfgArchiveSession::open(
            archive_path_, std::make_shared<FaultCfgIo>(failure, call));
        session.put("templates/replacement/en/page.html", "changed");

        EXPECT_THROW(session.save(), CfgTarError);
        EXPECT_TRUE(session.dirty());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "original");
    }
}

TEST_F(ArchiveSessionTest, PreservesActiveArchiveWhenOwnerCopyFails) {
    auto session = CfgArchiveSession::open(
        archive_path_,
        std::make_shared<FaultCfgIo>(FaultCfgIo::At::set_owner));
    session.put("templates/replacement/en/page.html", "changed");

    EXPECT_THROW(session.save(), CfgTarError);
    EXPECT_TRUE(session.dirty());
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("templates/replacement/en/page.html").data,
              "original");
}

TEST_F(ArchiveSessionTest, ActivePreRenameFailuresLeaveOldGenerationSelected) {
    using At = FaultCfgIo::At;
    const std::vector<std::pair<At, std::size_t>> failures {
        {At::create_temp, 2U},
        {At::set_mode, 2U},
        {At::set_owner, 1U},
        {At::write_error, 2U},
        {At::write_zero, 2U},
        {At::sync, 3U},
        {At::close, 5U},
        {At::replace, 2U},
    };

    for(const auto [failure, call] : failures) {
        SCOPED_TRACE(static_cast<int>(failure));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        auto session = CfgArchiveSession::open(
            archive_path_, std::make_shared<FaultCfgIo>(failure, call));
        session.put("templates/replacement/en/page.html", "changed");

        EXPECT_THROW(session.save(), CfgTarError);
        EXPECT_TRUE(session.dirty());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "original");
        EXPECT_EQ(CfgTar::read_file(archive_path_ + ".previous.bak.cftar")
                      .at("templates/replacement/en/page.html").data,
                  "original");
    }
}

TEST_F(ArchiveSessionTest, ActivePostRenameFailuresReportAmbiguousCommit) {
    using At = FaultCfgIo::At;
    for(const auto [failure, call] : {
            std::pair{At::open_directory, 3U},
            std::pair{At::sync, 4U},
            std::pair{At::close, 8U}}) {
        SCOPED_TRACE(static_cast<int>(failure));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        auto session = CfgArchiveSession::open(
            archive_path_, std::make_shared<FaultCfgIo>(failure, call));
        session.put("templates/replacement/en/page.html", "changed");

        EXPECT_THROW(session.save(), CfgTarError);

        // rename(2) already made the new generation visible. The failed
        // directory durability step cannot safely claim either rollback or a
        // durable commit, so the caller must reopen and inspect the archive.
        EXPECT_TRUE(session.dirty());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "changed");
        EXPECT_EQ(CfgTar::read_file(archive_path_ + ".previous.bak.cftar")
                      .at("templates/replacement/en/page.html").data,
                  "original");
    }
}

TEST_F(ArchiveSessionTest, RetriesInterruptedAndPartialWrites) {
    using At = FaultCfgIo::At;
    for(const auto interruption : {At::write_eintr, At::write_short}) {
        SCOPED_TRACE(static_cast<int>(interruption));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        auto session = CfgArchiveSession::open(
            archive_path_, std::make_shared<FaultCfgIo>(interruption));
        session.put("templates/replacement/en/page.html", "changed");

        EXPECT_NO_THROW(session.save());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "changed");
    }
}

TEST_F(ArchiveSessionTest, RefusesToOverwriteAnExternallyChangedArchive) {
    auto session = CfgArchiveSession::open(archive_path_);
    session.put("templates/replacement/en/page.html", "session change");

    auto external = valid_archive();
    external.replace("templates/replacement/en/page.html", "external change");
    ASSERT_EQ(::unlink(archive_path_.c_str()), 0);
    write_archive(external);

    EXPECT_THROW(session.save(), CfgTarError);
    EXPECT_EQ(CfgTar::read_file(archive_path_).at("templates/replacement/en/page.html").data,
              "external change");
    EXPECT_FALSE(std::filesystem::exists(archive_path_ + ".previous.bak.cftar"));
}

TEST_F(ArchiveSessionTest, RemovesResourcesAndReportsTheirChanges) {
    auto session = CfgArchiveSession::open(archive_path_);

    session.remove("templates/replacement/en/page.html");

    ASSERT_EQ(session.changes().size(), 1U);
    EXPECT_EQ(session.changes().front().kind,
              sx::cfg::CfgArchiveChange::Kind::removed);
    EXPECT_THROW(session.entry("templates/replacement/en/page.html"), CfgTarError);
    EXPECT_THROW(session.remove("templates/replacement/en/page.html"), CfgTarError);
}

TEST_F(ArchiveSessionTest, StableSidecarLockSerializesIndependentWriters) {
    auto first = CfgFileLock::acquire(archive_path_);

    EXPECT_THROW(
        CfgFileLock::acquire(archive_path_, std::chrono::milliseconds(30)),
        CfgTarError);
}

TEST_F(ArchiveSessionTest, SidecarLockHonorsDifferentWaitBudgets) {
    auto owner = CfgFileLock::acquire(archive_path_);

    for(const auto timeout : {std::chrono::milliseconds(0),
                              std::chrono::milliseconds(15),
                              std::chrono::milliseconds(70)}) {
        SCOPED_TRACE(timeout.count());
        const auto started = std::chrono::steady_clock::now();
        EXPECT_THROW(CfgFileLock::acquire(archive_path_, timeout), CfgTarError);
        const auto elapsed = std::chrono::steady_clock::now() - started;

        if(timeout.count() > 0) {
            // The polling interval is 25 ms, so expiration may overshoot the
            // requested budget by one scheduler turn but must never return early.
            EXPECT_GE(elapsed, timeout);
        }
        EXPECT_LT(elapsed, std::chrono::seconds(1));
    }
}

TEST_F(ArchiveSessionTest, LongCrossProcessOwnerOutlivesShortWaiter) {
    int ready[2] {-1, -1};
    ASSERT_EQ(::pipe(ready), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        ::close(ready[0]);
        try {
            auto lock = CfgFileLock::acquire(archive_path_);
            const char acquired = '1';
            if(::write(ready[1], &acquired, 1) != 1) _exit(2);
            std::this_thread::sleep_for(std::chrono::milliseconds(450));
            _exit(0);  // Kernel descriptor cleanup releases flock().
        }
        catch(...) {
            _exit(3);
        }
    }

    ::close(ready[1]);
    char acquired = 0;
    ASSERT_EQ(::read(ready[0], &acquired, 1), 1);
    ASSERT_EQ(acquired, '1');
    ::close(ready[0]);

    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(75)),
        CfgTarError);

    const auto long_wait_started = std::chrono::steady_clock::now();
    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::seconds(2)));
    const auto long_wait = std::chrono::steady_clock::now() - long_wait_started;
    EXPECT_GE(long_wait, std::chrono::milliseconds(250));
    EXPECT_LT(long_wait, std::chrono::seconds(2));

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(ArchiveSessionTest, KernelReleasesLockAfterOwnerIsKilled) {
    int ready[2] {-1, -1};
    ASSERT_EQ(::pipe(ready), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        ::close(ready[0]);
        try {
            auto lock = CfgFileLock::acquire(archive_path_);
            const char acquired = '1';
            if(::write(ready[1], &acquired, 1) != 1) _exit(2);
            for(;;) ::pause();
        }
        catch(...) {
            _exit(3);
        }
    }

    ::close(ready[1]);
    char acquired = 0;
    ASSERT_EQ(::read(ready[0], &acquired, 1), 1);
    ASSERT_EQ(acquired, '1');
    ::close(ready[0]);

    ASSERT_EQ(::kill(child, SIGKILL), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFSIGNALED(status));
    ASSERT_EQ(WTERMSIG(status), SIGKILL);

    // The stable sidecar remains on disk, but the dead process can no longer
    // own its kernel lock. A fresh administrator may enter immediately.
    EXPECT_TRUE(std::filesystem::is_regular_file(archive_path_ + ".lock"));
    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(100)));
}

TEST_F(ArchiveSessionTest, AbandonedUnlockedSidecarDoesNotBlockPublisher) {
    const auto sidecar = archive_path_ + ".lock";
    {
        std::ofstream stale(sidecar);
        stale << "old diagnostic text that has no locking authority\n";
    }

    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(100)));
    EXPECT_TRUE(std::filesystem::is_regular_file(sidecar));
}

TEST_F(ArchiveSessionTest, RemovingHeldSidecarDoesNotCreateSecondLockDomain) {
    int ready[2] {-1, -1};
    ASSERT_EQ(::pipe(ready), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if(child == 0) {
        ::close(ready[0]);
        try {
            auto lock = CfgFileLock::acquire(archive_path_);
            const char acquired = '1';
            if(::write(ready[1], &acquired, 1) != 1) _exit(2);
            std::this_thread::sleep_for(std::chrono::milliseconds(350));
            _exit(0);
        }
        catch(...) {
            _exit(3);
        }
    }

    ::close(ready[1]);
    char acquired = 0;
    ASSERT_EQ(::read(ready[0], &acquired, 1), 1);
    ASSERT_EQ(acquired, '1');
    ::close(ready[0]);

    // Simulate an administrator mistaking a slow publisher for a stale lock.
    // Removing the name must not let another process lock a fresh inode.
    ASSERT_TRUE(std::filesystem::remove(archive_path_ + ".lock"));
    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(75)),
        CfgTarError);

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);

    // Once the real owner exits, acquisition recreates the sidecar normally.
    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(250)));
    EXPECT_TRUE(std::filesystem::is_regular_file(archive_path_ + ".lock"));
}

TEST_F(ArchiveSessionTest, SlowPublicationMakesCompetingWriterTimeOutCleanly) {
    for(const auto slow_operation : {SlowCfgIo::At::write, SlowCfgIo::At::sync}) {
        SCOPED_TRACE(static_cast<int>(slow_operation));
        std::filesystem::remove(archive_path_);
        write_archive(valid_archive());
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");

        const auto io = std::make_shared<SlowCfgIo>(
            slow_operation, std::chrono::milliseconds(120));
        auto session = CfgArchiveSession::open(archive_path_, io);
        session.put("templates/replacement/en/page.html", "slow but valid");
        std::exception_ptr save_error;
        std::thread publisher([&] {
            try {
                session.save();
            }
            catch(...) {
                save_error = std::current_exception();
            }
        });

        const bool entered_io = io->wait_until_entered(std::chrono::seconds(1));
        if(!entered_io) {
            publisher.join();
            FAIL() << "publisher did not enter the delayed I/O operation";
        }
        const auto wait_started = std::chrono::steady_clock::now();
        EXPECT_THROW(
            CfgFileLock::acquire(
                archive_path_, std::chrono::milliseconds(35)),
            CfgTarError);
        const auto waited = std::chrono::steady_clock::now() - wait_started;
        EXPECT_GE(waited, std::chrono::milliseconds(25));
        EXPECT_LT(waited, std::chrono::seconds(1));

        publisher.join();
        if(save_error) std::rethrow_exception(save_error);
        EXPECT_FALSE(session.dirty());
        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "slow but valid");
        EXPECT_EQ(CfgTar::read_file(archive_path_ + ".previous.bak.cftar")
                      .at("templates/replacement/en/page.html").data,
                  "original");
    }
}

TEST_F(ArchiveSessionTest, PublicationLongerThanLockWaitDoesNotLoseOwnership) {
    const auto io = std::make_shared<SlowCfgIo>(
        SlowCfgIo::At::write, std::chrono::milliseconds(5200), 1);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "slow generation");
    std::exception_ptr save_error;
    std::thread publisher([&] {
        try {
            session.save();
        }
        catch(...) {
            save_error = std::current_exception();
        }
    });

    if(!io->wait_until_entered(std::chrono::seconds(1))) {
        publisher.join();
        FAIL() << "publisher did not enter the delayed write";
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Five seconds is the acquisition wait budget, not a lock lifetime. The
    // original publisher must still own both kernel locks after that period.
    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(75)),
        CfgTarError);

    publisher.join();
    if(save_error) std::rethrow_exception(save_error);
    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "slow generation");
}

TEST_F(ArchiveSessionTest, DetectsManualReplacementDuringSlowRecoveryWrite) {
    const auto io = std::make_shared<SlowCfgIo>(
        SlowCfgIo::At::write, std::chrono::milliseconds(250), 1);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "session generation");
    std::exception_ptr save_error;
    std::thread publisher([&] {
        try {
            session.save();
        }
        catch(...) {
            save_error = std::current_exception();
        }
    });

    if(!io->wait_until_entered(std::chrono::seconds(1))) {
        publisher.join();
        FAIL() << "publisher did not enter the delayed recovery write";
    }
    auto external = valid_archive();
    external.upsert("templates/replacement/en/page.html", "manual admin generation");
    const auto manual_path = archive_path_ + ".manual-replacement";
    external.write_file(manual_path);
    if(::rename(manual_path.c_str(), archive_path_.c_str()) != 0) {
        publisher.join();
        FAIL() << "cannot install the manual replacement archive";
    }

    publisher.join();
    ASSERT_TRUE(save_error);
    EXPECT_THROW(std::rethrow_exception(save_error), CfgTarError);
    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "manual admin generation");
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, DetectsActiveArchiveRemovalDuringSlowRecoveryWrite) {
    const auto io = std::make_shared<SlowCfgIo>(
        SlowCfgIo::At::write, std::chrono::milliseconds(250), 1);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "session generation");
    std::exception_ptr save_error;
    std::thread publisher([&] {
        try {
            session.save();
        }
        catch(...) {
            save_error = std::current_exception();
        }
    });

    if(!io->wait_until_entered(std::chrono::seconds(1))) {
        publisher.join();
        FAIL() << "publisher did not enter the delayed recovery write";
    }
    ASSERT_TRUE(std::filesystem::remove(archive_path_));

    publisher.join();
    ASSERT_TRUE(save_error);
    EXPECT_THROW(std::rethrow_exception(save_error), CfgTarError);
    EXPECT_FALSE(std::filesystem::exists(archive_path_));
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, DetectsActiveArchiveSymlinkDuringSlowRecoveryWrite) {
    const auto io = std::make_shared<SlowCfgIo>(
        SlowCfgIo::At::write, std::chrono::milliseconds(250), 1);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "session generation");
    std::exception_ptr save_error;
    std::thread publisher([&] {
        try {
            session.save();
        }
        catch(...) {
            save_error = std::current_exception();
        }
    });

    if(!io->wait_until_entered(std::chrono::seconds(1))) {
        publisher.join();
        FAIL() << "publisher did not enter the delayed recovery write";
    }
    const auto manual_target = archive_path_ + ".manual-target";
    ASSERT_EQ(::rename(archive_path_.c_str(), manual_target.c_str()), 0);
    ASSERT_EQ(::symlink(manual_target.c_str(), archive_path_.c_str()), 0);

    publisher.join();
    ASSERT_TRUE(save_error);
    EXPECT_THROW(std::rethrow_exception(save_error), CfgTarError);
    EXPECT_TRUE(std::filesystem::is_symlink(archive_path_));
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, RemovedRecoveryPreventsActivePublication) {
    const auto io = std::make_shared<MutatingCfgIo>(
        MutatingCfgIo::Action::remove_recovery_after_replace);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "must not publish");

    EXPECT_THROW(session.save(), CfgTarError);

    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "original");
    EXPECT_FALSE(std::filesystem::exists(
        archive_path_ + ".previous.bak.cftar"));
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, ReplacedRecoveryPreventsActivePublication) {
    const auto io = std::make_shared<MutatingCfgIo>(
        MutatingCfgIo::Action::corrupt_recovery_after_replace);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "must not publish");

    EXPECT_THROW(session.save(), CfgTarError);

    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "original");
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, RemovedTemporaryFileCannotPublish) {
    const auto io = std::make_shared<MutatingCfgIo>(
        MutatingCfgIo::Action::remove_temporary_during_write);
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "must not publish");

    EXPECT_THROW(session.save(), CfgTarError);

    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "original");
    EXPECT_TRUE(session.dirty());
}

TEST_F(ArchiveSessionTest, ProcessDeathLeavesAConsistentPublicationBoundary) {
    using After = KillPointCfgIo::After;
    for(const auto kill_point : {
            After::directory_lock,
            After::recovery_replace,
            After::active_replace}) {
        SCOPED_TRACE(static_cast<int>(kill_point));
        std::filesystem::remove(archive_path_);
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        write_archive(valid_archive());

        int ready[2] {-1, -1};
        ASSERT_EQ(::pipe(ready), 0);
        const pid_t child = ::fork();
        ASSERT_GE(child, 0);
        if(child == 0) {
            ::close(ready[0]);
            try {
                const auto io = std::make_shared<KillPointCfgIo>(
                    kill_point, archive_path_, ready[1]);
                auto session = CfgArchiveSession::open(archive_path_, io);
                session.put("templates/replacement/en/page.html", "killed generation");
                session.save();
                _exit(91);
            }
            catch(...) {
                _exit(92);
            }
        }

        ::close(ready[1]);
        char reached = 0;
        ASSERT_EQ(::read(ready[0], &reached, 1), 1);
        ASSERT_EQ(reached, '1');
        ::close(ready[0]);
        ASSERT_EQ(::kill(child, SIGKILL), 0);
        int status = 0;
        ASSERT_EQ(::waitpid(child, &status, 0), child);
        ASSERT_TRUE(WIFSIGNALED(status));
        ASSERT_EQ(WTERMSIG(status), SIGKILL);

        const auto active = CfgTar::read_file(archive_path_);
        const auto active_value = active.at("templates/replacement/en/page.html").data;
        if(kill_point == After::active_replace) {
            EXPECT_EQ(active_value, "killed generation");
        }
        else {
            EXPECT_EQ(active_value, "original");
        }

        const auto recovery_path = archive_path_ + ".previous.bak.cftar";
        if(kill_point == After::directory_lock) {
            EXPECT_FALSE(std::filesystem::exists(recovery_path));
        }
        else {
            EXPECT_EQ(CfgTar::read_file(recovery_path)
                          .at("templates/replacement/en/page.html").data,
                      "original");
        }

        // Kernel cleanup after SIGKILL must make the next administrative
        // operation possible regardless of the interrupted phase.
        EXPECT_NO_THROW(CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(100)));
    }
}

TEST_F(ArchiveSessionTest, ResourceExhaustionPreservesActiveGeneration) {
    using At = ResourceFailureCfgIo::At;
    const std::vector<std::pair<At, int>> failures {
        {At::write, ENOSPC},
        {At::write, EDQUOT},
        {At::create_temp, EROFS},
        {At::open_directory, EMFILE},
    };

    for(const auto [operation, error] : failures) {
        SCOPED_TRACE(error);
        std::filesystem::remove(archive_path_);
        std::filesystem::remove(archive_path_ + ".previous.bak.cftar");
        write_archive(valid_archive());
        const auto io = std::make_shared<ResourceFailureCfgIo>(operation, error);
        auto session = CfgArchiveSession::open(archive_path_, io);
        session.put("templates/replacement/en/page.html", "must not publish");

        EXPECT_THROW(session.save(), CfgTarError);

        EXPECT_EQ(CfgTar::read_file(archive_path_)
                      .at("templates/replacement/en/page.html").data,
                  "original");
        EXPECT_TRUE(session.dirty());
        EXPECT_NO_THROW(CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(100)));
    }
}

TEST_F(ArchiveSessionTest, SlowFailingSyncKeepsCompetingWriterOut) {
    const auto io = std::make_shared<ResourceFailureCfgIo>(
        ResourceFailureCfgIo::At::sync,
        ENOSPC,
        1,
        std::chrono::milliseconds(250));
    auto session = CfgArchiveSession::open(archive_path_, io);
    session.put("templates/replacement/en/page.html", "must not publish");
    std::exception_ptr save_error;
    std::thread publisher([&] {
        try {
            session.save();
        }
        catch(...) {
            save_error = std::current_exception();
        }
    });

    if(!io->wait_until_entered(std::chrono::seconds(1))) {
        publisher.join();
        FAIL() << "publisher did not enter the delayed failing fsync";
    }
    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(75)),
        CfgTarError);

    publisher.join();
    ASSERT_TRUE(save_error);
    EXPECT_THROW(std::rethrow_exception(save_error), CfgTarError);
    EXPECT_EQ(CfgTar::read_file(archive_path_)
                  .at("templates/replacement/en/page.html").data,
              "original");
    EXPECT_TRUE(session.dirty());
    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(100)));
}

TEST_F(ArchiveSessionTest, ReleasedSidecarLockCanBeAcquiredAgain) {
    {
        auto first = CfgFileLock::acquire(archive_path_);
    }

    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(30)));
}

TEST_F(ArchiveSessionTest, SidecarLockRejectsSymlinkAndSupportsMoveAssignment) {
    const auto other_directory = directory_ + "/other";
    std::filesystem::create_directory(other_directory);
    const auto other_path = other_directory + "/other.cftar";
    ASSERT_EQ(::symlink(archive_path_.c_str(), (other_path + ".lock").c_str()), 0);
    EXPECT_THROW(CfgFileLock::acquire(other_path), CfgTarError);

    auto first = CfgFileLock::acquire(archive_path_);
    const auto move_directory = directory_ + "/move-target";
    std::filesystem::create_directory(move_directory);
    auto second = CfgFileLock::acquire(move_directory + "/second.cftar");
    second = std::move(first);
    EXPECT_THROW(
        CfgFileLock::acquire(archive_path_, std::chrono::milliseconds(30)),
        CfgTarError);
}

TEST_F(ArchiveSessionTest, SidecarLockReportsInjectedOpenAndLockFailures) {
    using At = FaultCfgIo::At;
    for(const auto failure : {At::open_lock, At::lock_error}) {
        SCOPED_TRACE(static_cast<int>(failure));
        EXPECT_THROW(
            CfgFileLock::acquire(
                archive_path_, std::chrono::milliseconds(30),
                std::make_shared<FaultCfgIo>(failure)),
            CfgTarError);
    }
    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_, std::chrono::milliseconds(30), nullptr),
        CfgTarError);

    // The directory anchor may succeed while the narrower sidecar lock fails.
    // Both descriptors must still be cleaned up by the exception path.
    EXPECT_THROW(
        CfgFileLock::acquire(
            archive_path_,
            std::chrono::milliseconds(30),
            std::make_shared<FaultCfgIo>(At::lock_error, 2)),
        CfgTarError);
    EXPECT_NO_THROW(CfgFileLock::acquire(
        archive_path_, std::chrono::milliseconds(100)));
}

TEST_F(ArchiveSessionTest, SidecarLockMoveConstructionTransfersOwnership) {
    auto first = CfgFileLock::acquire(archive_path_);
    auto moved = std::move(first);

    EXPECT_THROW(
        CfgFileLock::acquire(archive_path_, std::chrono::milliseconds(30)),
        CfgTarError);
}

TEST_F(ArchiveSessionTest, ExposureIsReadOnlyAndLivesOnlyInRegistry) {
    const auto session = CfgArchiveSession::open(archive_path_);
    CfgExposureRegistry exposures;

    const auto exposure = exposures.expose(
        session.archive(), "templates/replacement/en/page.html");
    struct stat metadata {};
    ASSERT_EQ(::stat(exposure.filesystem_path.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0400);
    EXPECT_TRUE(std::filesystem::exists(exposure.filesystem_path));

    EXPECT_TRUE(exposures.close(exposure.id));
    EXPECT_FALSE(std::filesystem::exists(exposure.filesystem_path));
}

TEST_F(ArchiveSessionTest, RegistryDestructionClosesAllExposures) {
    const auto session = CfgArchiveSession::open(archive_path_);
    std::string path;
    {
        CfgExposureRegistry exposures;
        path = exposures.expose(session.archive(), "templates").filesystem_path;
        EXPECT_TRUE(std::filesystem::exists(path));
    }
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(ArchiveSessionTest, ExposureRegistryListsAndClosesMultipleTrees) {
    const auto session = CfgArchiveSession::open(archive_path_);
    CfgExposureRegistry exposures;

    const auto first = exposures.expose(session.archive(), "templates/replacement/en/page.html");
    const auto second = exposures.expose(session.archive(), "templates");
    const auto entries = exposures.entries();

    EXPECT_EQ(entries.size(), 2U);
    EXPECT_FALSE(exposures.close(9999));
    exposures.close_all();
    EXPECT_TRUE(exposures.entries().empty());
    EXPECT_FALSE(std::filesystem::exists(first.filesystem_path));
    EXPECT_FALSE(std::filesystem::exists(second.filesystem_path));
}

TEST_F(ArchiveSessionTest, ExposureRejectsMissingLogicalPath) {
    const auto session = CfgArchiveSession::open(archive_path_);
    CfgExposureRegistry exposures;

    EXPECT_THROW(exposures.expose(session.archive(), "templates/missing"), CfgTarError);
    EXPECT_TRUE(exposures.entries().empty());
}

}  // namespace
