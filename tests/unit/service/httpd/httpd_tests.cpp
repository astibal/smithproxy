#include <gtest/gtest.h>

#include <service/httpd/httpd.hpp>
#include <service/httpd/admin_enrollment.hpp>
#include <service/httpd/handlers/handlers.hpp>
#include <service/httpd/login_throttle.hpp>
#include <service/httpd/wh/webhook_lease.hpp>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <set>
#include <sys/socket.h>

namespace {

using sx::webserver::HttpSessions;
using sx::webserver::LoginThrottle;
using sx::webserver::TimedOptional;
using sx::webserver::WebhookOverrideLease;

std::set<int> listening_sockets() {
    std::set<int> result;
    std::error_code error;
    for(std::filesystem::directory_iterator entry("/proc/self/fd", error), end;
        not error && entry != end; entry.increment(error)) {
        auto const name = entry->path().filename().string();
        char* tail = nullptr;
        errno = 0;
        auto const value = std::strtol(name.c_str(), &tail, 10);
        if(errno or tail == name.c_str() or *tail != '\0' or value < 0) continue;

        int accepting = 0;
        socklen_t accepting_size = sizeof(accepting);
        if(::getsockopt(static_cast<int>(value), SOL_SOCKET, SO_ACCEPTCONN,
                        &accepting, &accepting_size) == 0 && accepting) {
            result.emplace(static_cast<int>(value));
        }
    }
    return result;
}

std::set<int> new_listening_sockets(std::set<int> const& before) {
    auto const after = listening_sockets();
    std::set<int> result;
    std::set_difference(after.begin(), after.end(), before.begin(), before.end(),
                        std::inserter(result, result.end()));
    return result;
}

unsigned short listening_port(int descriptor) {
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if(::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &size) != 0)
        return 0;
    return ntohs(address.sin_port);
}

int request_status(unsigned short port) {
    const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(descriptor < 0) return 0;
    timeval timeout{2, 0};
    ::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if(::connect(descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(descriptor);
        return 0;
    }
    constexpr std::string_view request =
        "GET /missing HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if(::send(descriptor, request.data(), request.size(), MSG_NOSIGNAL) !=
       static_cast<ssize_t>(request.size())) {
        ::close(descriptor);
        return 0;
    }
    std::array<char, 128> response{};
    const auto received = ::recv(descriptor, response.data(), response.size() - 1, 0);
    ::close(descriptor);
    if(received <= 0) return 0;
    int status = 0;
    return std::sscanf(response.data(), "HTTP/%*s %d", &status) == 1 ? status : 0;
}

class HttpSessionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::admin_api_keys.clear();
        HttpSessions::archive_keys.clear();
        HttpSessions::administrator_generations.clear();
        HttpSessions::extend_on_access = false;
    }

    void TearDown() override {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys.clear();
        HttpSessions::api_keys.clear();
        HttpSessions::admin_api_keys.clear();
        HttpSessions::archive_keys.clear();
        HttpSessions::administrator_generations.clear();
        HttpSessions::extend_on_access = true;
    }
};

TEST_F(HttpSessionsTest, ExpiredValuesAreRejectedAndRemoved) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf"] = TimedOptional<std::string>("token", 0);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf"), "");
    HttpSessions::cleanup();

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_TRUE(HttpSessions::access_keys.empty());
}

TEST_F(HttpSessionsTest, ValidValuesAndApiKeySnapshotsRoundTrip) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_EQ(HttpSessions::table_value("auth", "csrf_token"), "token");
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));

    HttpSessions::replace_api_keys({"one", "two"});
    EXPECT_TRUE(HttpSessions::has_api_keys());
    EXPECT_TRUE(HttpSessions::has_api_key("one"));
    EXPECT_FALSE(HttpSessions::has_api_key("missing"));
    EXPECT_EQ(HttpSessions::api_keys_snapshot(),
              (std::set<std::string>{"one", "two"}));
}

TEST_F(HttpSessionsTest, InvalidCsrfDoesNotDestroyOtherwiseValidSession) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["auth"]["csrf_token"] = TimedOptional<std::string>("token", 60);
    }

    EXPECT_FALSE(HttpSessions::validate_tokens("auth", "wrong"));
    EXPECT_TRUE(HttpSessions::validate_tokens("auth", "token"));
}

TEST(HttpAuthorizationTest, EveryUnsafeMethodRequiresCsrfHeader) {
    using sx::webserver::authorized::request_requires_csrf_header;

    EXPECT_FALSE(request_requires_csrf_header("GET"));
    EXPECT_FALSE(request_requires_csrf_header("HEAD"));
    EXPECT_FALSE(request_requires_csrf_header("OPTIONS"));
    EXPECT_TRUE(request_requires_csrf_header("POST"));
    EXPECT_TRUE(request_requires_csrf_header("PUT"));
    EXPECT_TRUE(request_requires_csrf_header("PATCH"));
    EXPECT_TRUE(request_requires_csrf_header("DELETE"));
    EXPECT_TRUE(request_requires_csrf_header("CONNECT"));
}

TEST(HttpResponderTest, RecognizesEverySupportedBodyBearingMethod) {
    using lmh::request_method_accepts_body;

    EXPECT_FALSE(request_method_accepts_body("GET"));
    EXPECT_FALSE(request_method_accepts_body("HEAD"));
    EXPECT_FALSE(request_method_accepts_body("OPTIONS"));
    EXPECT_TRUE(request_method_accepts_body("POST"));
    EXPECT_TRUE(request_method_accepts_body("PUT"));
    EXPECT_TRUE(request_method_accepts_body("PATCH"));
    EXPECT_TRUE(request_method_accepts_body("DELETE"));
    EXPECT_FALSE(request_method_accepts_body("CONNECT"));
}

TEST_F(HttpSessionsTest, ApiKeyCapabilitiesRemainIndependent) {
    HttpSessions::replace_api_keys({"ordinary"});
    HttpSessions::replace_admin_api_keys({"management"});
    HttpSessions::replace_archive_keys({"backup"});

    EXPECT_TRUE(HttpSessions::has_standard_key("ordinary"));
    EXPECT_FALSE(HttpSessions::has_admin_key("ordinary"));
    EXPECT_FALSE(HttpSessions::has_archive_key("ordinary"));

    EXPECT_TRUE(HttpSessions::has_standard_key("management"));
    EXPECT_TRUE(HttpSessions::has_admin_key("management"));
    EXPECT_FALSE(HttpSessions::has_archive_key("management"));

    EXPECT_FALSE(HttpSessions::has_standard_key("backup"));
    EXPECT_FALSE(HttpSessions::has_admin_key("backup"));
    EXPECT_TRUE(HttpSessions::has_archive_key("backup"));
    EXPECT_TRUE(HttpSessions::has_any_key("backup"));
    EXPECT_EQ(HttpSessions::archive_keys_snapshot(),
              (std::set<std::string>{"backup"}));
}

TEST_F(HttpSessionsTest, StandardSessionCapabilityIsExplicit) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        auto& ordinary = HttpSessions::access_keys["ordinary"];
        ordinary["csrf_token"] = TimedOptional<std::string>("ordinary-csrf", 60);
        ordinary[HttpSessions::ATT_STANDARD_ACCESS] =
            TimedOptional<std::string>("1", 60);

        auto& archive = HttpSessions::access_keys["archive"];
        archive["csrf_token"] = TimedOptional<std::string>("archive-csrf", 60);
        archive[HttpSessions::ATT_STANDARD_ACCESS] =
            TimedOptional<std::string>("0", 60);
        archive[HttpSessions::ATT_ARCHIVE_ACCESS] =
            TimedOptional<std::string>("1", 60);
    }

    EXPECT_TRUE(HttpSessions::validate_standard_tokens("ordinary", "ordinary-csrf"));
    EXPECT_FALSE(HttpSessions::validate_archive_tokens("ordinary", "ordinary-csrf"));
    EXPECT_FALSE(HttpSessions::validate_standard_tokens("archive", "archive-csrf"));
    EXPECT_TRUE(HttpSessions::validate_archive_tokens("archive", "archive-csrf"));
}

TEST_F(HttpSessionsTest, ArchiveCapabilityRequiresValidCsrfAndExplicitGrant) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["ordinary"]["csrf_token"] =
            TimedOptional<std::string>("ordinary-csrf", 60);
        HttpSessions::access_keys["ordinary"]["archive_access"] =
            TimedOptional<std::string>("0", 60);
        HttpSessions::access_keys["archive"]["csrf_token"] =
            TimedOptional<std::string>("archive-csrf", 60);
        HttpSessions::access_keys["archive"]["archive_access"] =
            TimedOptional<std::string>("1", 60);
    }

    EXPECT_FALSE(HttpSessions::validate_archive_tokens(
        "ordinary", "ordinary-csrf"));
    EXPECT_FALSE(HttpSessions::validate_archive_tokens(
        "archive", "wrong-csrf"));
    EXPECT_TRUE(HttpSessions::validate_archive_tokens(
        "archive", "archive-csrf"));
}

TEST_F(HttpSessionsTest, AdministratorCapabilityIsIndependentFromOrdinaryAccess) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["ordinary"]["csrf_token"] =
            TimedOptional<std::string>("ordinary-csrf", 60);
        HttpSessions::access_keys["ordinary"]["administrator_access"] =
            TimedOptional<std::string>("0", 60);
        HttpSessions::access_keys["administrator"]["csrf_token"] =
            TimedOptional<std::string>("administrator-csrf", 60);
        HttpSessions::access_keys["administrator"]["administrator_access"] =
            TimedOptional<std::string>("1", 60);
    }

    EXPECT_FALSE(HttpSessions::validate_admin_tokens(
        "ordinary", "ordinary-csrf"));
    EXPECT_FALSE(HttpSessions::validate_admin_tokens(
        "administrator", "wrong-csrf"));
    EXPECT_TRUE(HttpSessions::validate_admin_tokens(
        "administrator", "administrator-csrf"));
}

TEST_F(HttpSessionsTest, RevokesOnlySessionsForSelectedManagedAdministrator) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["alice-one"][HttpSessions::ATT_ADMINISTRATOR_NAME] =
            TimedOptional<std::string>("alice", 60);
        HttpSessions::access_keys["alice-two"][HttpSessions::ATT_ADMINISTRATOR_NAME] =
            TimedOptional<std::string>("alice", 60);
        HttpSessions::access_keys["bob"][HttpSessions::ATT_ADMINISTRATOR_NAME] =
            TimedOptional<std::string>("bob", 60);
        HttpSessions::access_keys["pam-or-boot"]["administrator_access"] =
            TimedOptional<std::string>("1", 60);
    }

    EXPECT_EQ(HttpSessions::revoke_administrator_sessions("alice"), 2U);

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_EQ(HttpSessions::access_keys.find("alice-one"),
              HttpSessions::access_keys.end());
    EXPECT_EQ(HttpSessions::access_keys.find("alice-two"),
              HttpSessions::access_keys.end());
    EXPECT_NE(HttpSessions::access_keys.find("bob"), HttpSessions::access_keys.end());
    EXPECT_NE(HttpSessions::access_keys.find("pam-or-boot"),
              HttpSessions::access_keys.end());
}

TEST_F(HttpSessionsTest, RejectsManagedSessionPublishedAfterCredentialChange) {
    const auto authenticated_generation =
        HttpSessions::administrator_generation("alice");
    EXPECT_EQ(authenticated_generation, 0U);
    EXPECT_EQ(HttpSessions::administrator_changed("alice"), 1U);

    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        auto& stale = HttpSessions::access_keys["late-alice"];
        stale["csrf_token"] = TimedOptional<std::string>("alice-csrf", 60);
        stale[HttpSessions::ATT_ADMINISTRATOR_NAME] =
            TimedOptional<std::string>("alice", 60);
        stale[HttpSessions::ATT_ADMINISTRATOR_GENERATION] =
            TimedOptional<std::string>(std::to_string(authenticated_generation), 60);

        auto& current = HttpSessions::access_keys["current-alice"];
        current["csrf_token"] = TimedOptional<std::string>("current-csrf", 60);
        current[HttpSessions::ATT_ADMINISTRATOR_NAME] =
            TimedOptional<std::string>("alice", 60);
        current[HttpSessions::ATT_ADMINISTRATOR_GENERATION] =
            TimedOptional<std::string>("1", 60);

        HttpSessions::access_keys["boot-key"]["csrf_token"] =
            TimedOptional<std::string>("boot-csrf", 60);
    }

    EXPECT_FALSE(HttpSessions::validate_tokens("late-alice", "alice-csrf"));
    EXPECT_TRUE(HttpSessions::validate_tokens("current-alice", "current-csrf"));
    EXPECT_TRUE(HttpSessions::validate_tokens("boot-key", "boot-csrf"));

    auto lock = std::scoped_lock(HttpSessions::lock);
    EXPECT_EQ(HttpSessions::access_keys.find("late-alice"),
              HttpSessions::access_keys.end());
}

TEST_F(HttpSessionsTest, CarriesAuthenticatedActorOnlyInsideResponderScope) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        auto& session = HttpSessions::access_keys["managed-session"];
        session[HttpSessions::ATT_PRINCIPAL] =
            TimedOptional<std::string>("alice", 60);
        session[HttpSessions::ATT_AUTHENTICATION_METHOD] =
            TimedOptional<std::string>("password", 60);
    }

    const auto actor = sx::webserver::authorized::session_actor("managed-session");
    EXPECT_EQ(actor.principal, "alice");
    EXPECT_EQ(actor.authentication_method, "password");
    EXPECT_EQ(sx::webserver::authorized::current_actor().principal, "<unknown>");

    {
        const sx::webserver::authorized::ActorScope scope(actor);
        EXPECT_EQ(sx::webserver::authorized::current_actor().principal, "alice");
        EXPECT_EQ(
            sx::webserver::authorized::current_actor().authentication_method,
            "password");
        {
            const sx::webserver::authorized::ActorScope nested(
                sx::webserver::authorized::api_key_actor());
            EXPECT_EQ(
                sx::webserver::authorized::current_actor().principal,
                "api-key");
        }
        EXPECT_EQ(sx::webserver::authorized::current_actor().principal, "alice");
    }
    EXPECT_EQ(sx::webserver::authorized::current_actor().principal, "<unknown>");
}

TEST_F(HttpSessionsTest, DescribesCredentialSessionsWithoutLoggingTheirSecret) {
    const auto session = sx::webserver::authorized::session_actor("missing-secret");
    EXPECT_EQ(session.principal, "authenticated-session");
    EXPECT_EQ(session.authentication_method, "session");

    const auto api_key = sx::webserver::authorized::api_key_actor();
    EXPECT_EQ(api_key.principal, "api-key");
    EXPECT_EQ(api_key.authentication_method, "api_key");
}

TEST_F(HttpSessionsTest, RevokesOneExplicitSessionWithoutTouchingOthers) {
    {
        auto lock = std::scoped_lock(HttpSessions::lock);
        HttpSessions::access_keys["current"]["csrf_token"] =
            TimedOptional<std::string>("current-csrf", 60);
        HttpSessions::access_keys["other"]["csrf_token"] =
            TimedOptional<std::string>("other-csrf", 60);
    }

    EXPECT_TRUE(HttpSessions::revoke_session("current"));
    EXPECT_FALSE(HttpSessions::revoke_session("current"));
    EXPECT_FALSE(HttpSessions::revoke_session(""));
    EXPECT_TRUE(HttpSessions::validate_tokens("other", "other-csrf"));
}

TEST_F(HttpSessionsTest, ArchiveKeyLoadsOnceFromEnvironmentAndIsRemoved) {
    const std::string secret(32, 'a');
    ASSERT_EQ(::setenv("SMITHPROXY_ARCHIVE_API_KEY", secret.c_str(), 1), 0);

    EXPECT_TRUE(HttpSessions::load_archive_key_from_environment());
    EXPECT_EQ(::getenv("SMITHPROXY_ARCHIVE_API_KEY"), nullptr);
    EXPECT_TRUE(HttpSessions::has_archive_key(secret));
    EXPECT_FALSE(HttpSessions::has_standard_key(secret));
    EXPECT_FALSE(HttpSessions::has_admin_key(secret));
}

TEST_F(HttpSessionsTest, ShortArchiveEnvironmentKeyIsRejectedAndRemoved) {
    ASSERT_EQ(::setenv("SMITHPROXY_ARCHIVE_API_KEY", "too-short", 1), 0);

    EXPECT_FALSE(HttpSessions::load_archive_key_from_environment());
    EXPECT_EQ(::getenv("SMITHPROXY_ARCHIVE_API_KEY"), nullptr);
    EXPECT_TRUE(HttpSessions::archive_keys_snapshot().empty());
}

TEST_F(HttpSessionsTest, GeneratedTokensAreNonEmptyAndIndependent) {
    auto const auth = HttpSessions::generate_auth_token();
    auto const csrf = HttpSessions::generate_csrf_token();

    EXPECT_EQ(auth.size(), 32U);
    EXPECT_EQ(csrf.size(), 32U);
    EXPECT_NE(auth, csrf);
}

class LoginThrottleTest : public testing::Test {
protected:
    void SetUp() override { LoginThrottle::instance().clear(); }
    void TearDown() override { LoginThrottle::instance().clear(); }
};

TEST_F(LoginThrottleTest, LimitsOnePrincipalAndResetsAfterTheWindow) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t attempt = 0; attempt < LoginThrottle::principal_attempt_limit;
        ++attempt) {
        EXPECT_TRUE(throttle.permit("192.0.2.1", "alice", 1000).allowed);
    }

    const auto denied = throttle.permit("192.0.2.1", "alice", 1000);
    EXPECT_FALSE(denied.allowed);
    EXPECT_EQ(denied.retry_after_seconds, LoginThrottle::window_seconds);
    EXPECT_TRUE(throttle.permit("192.0.2.1", "alice", 1060).allowed);
}

TEST_F(LoginThrottleTest, DoesNotLockAPrincipalOutFromAnotherSource) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t attempt = 0; attempt < LoginThrottle::principal_attempt_limit;
        ++attempt) {
        EXPECT_TRUE(throttle.permit("192.0.2.10", "alice", 1500).allowed);
    }

    EXPECT_FALSE(throttle.permit("192.0.2.10", "alice", 1500).allowed);
    EXPECT_TRUE(throttle.permit("192.0.2.11", "alice", 1500).allowed);
}

TEST_F(LoginThrottleTest, LimitsRotatingPrincipalsFromOneSource) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t attempt = 0; attempt < LoginThrottle::source_attempt_limit;
        ++attempt) {
        EXPECT_TRUE(throttle.permit(
            "192.0.2.2", "user-" + std::to_string(attempt), 2000).allowed);
    }

    const auto denied = throttle.permit("192.0.2.2", "another-user", 2000);
    EXPECT_FALSE(denied.allowed);
    EXPECT_EQ(denied.retry_after_seconds, LoginThrottle::window_seconds);
}

TEST_F(LoginThrottleTest, SuccessfulPrincipalDoesNotResetSourceCpuBudget) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t attempt = 0; attempt < LoginThrottle::principal_attempt_limit;
        ++attempt) {
        EXPECT_TRUE(throttle.permit("192.0.2.3", "alice", 3000).allowed);
    }
    throttle.record_success("192.0.2.3", "alice");

    EXPECT_TRUE(throttle.permit("192.0.2.3", "alice", 3000).allowed);
    const auto counts = throttle.entry_counts(3000);
    EXPECT_EQ(counts.first, 1U);
    EXPECT_EQ(counts.second, 1U);
}

TEST_F(LoginThrottleTest, BoundsRuntimeStateUnderHostileIdentifiers) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t index = 0; index < LoginThrottle::capacity + 50U; ++index) {
        throttle.permit(
            "source-" + std::to_string(index),
            "principal-" + std::to_string(index), 4000);
    }

    const auto counts = throttle.entry_counts(4000);
    EXPECT_EQ(counts.first, LoginThrottle::capacity);
    EXPECT_EQ(counts.second, LoginThrottle::capacity);
}

TEST_F(LoginThrottleTest, CollapsesOversizedSourceIdentifiersIntoOneBudget) {
    auto& throttle = LoginThrottle::instance();
    for(std::size_t attempt = 0; attempt < LoginThrottle::source_attempt_limit;
        ++attempt) {
        auto source = std::string(LoginThrottle::maximum_source_key_bytes + 1U, 'a');
        source += std::to_string(attempt);
        EXPECT_TRUE(throttle.permit(
            source, "principal-" + std::to_string(attempt), 5000).allowed);
    }

    const auto denied = throttle.permit(
        std::string(LoginThrottle::maximum_source_key_bytes + 2U, 'b'),
        "another-principal", 5000);
    EXPECT_FALSE(denied.allowed);
    EXPECT_EQ(denied.retry_after_seconds, LoginThrottle::window_seconds);
}

class AdminEnrollmentStoreTest : public testing::Test {
protected:
    void SetUp() override { sx::webserver::AdminEnrollmentStore::instance().clear(); }
    void TearDown() override { sx::webserver::AdminEnrollmentStore::instance().clear(); }
};

TEST_F(AdminEnrollmentStoreTest, IssuesAndConsumesOneCapabilityExactlyOnce) {
    auto& store = sx::webserver::AdminEnrollmentStore::instance();
    const auto issued = store.issue("security-admin", 1000, 60);
    ASSERT_TRUE(issued);
    EXPECT_EQ(issued->token.size(), 64U);
    EXPECT_EQ(issued->expires_at_unix_seconds, 1060);
    EXPECT_EQ(store.size(1000), 1U);

    EXPECT_EQ(store.consume(issued->token, 1059), "security-admin");
    EXPECT_FALSE(store.consume(issued->token, 1059));
    EXPECT_EQ(store.size(1059), 0U);
}

TEST_F(AdminEnrollmentStoreTest, ReservationBlocksReuseAndRollsBackWithoutCommit) {
    auto& store = sx::webserver::AdminEnrollmentStore::instance();
    const auto issued = store.issue("security-admin", 1000, 60);
    ASSERT_TRUE(issued);

    {
        auto reservation = store.reserve(issued->token, 1001);
        ASSERT_TRUE(reservation);
        EXPECT_EQ(reservation->administrator(), "security-admin");
        EXPECT_FALSE(store.reserve(issued->token, 1001));
    }

    auto retry = store.reserve(issued->token, 1002);
    ASSERT_TRUE(retry);
    EXPECT_TRUE(retry->commit());
    EXPECT_FALSE(store.reserve(issued->token, 1002));
}

TEST_F(AdminEnrollmentStoreTest, ClearInvalidatesOutstandingReservation) {
    auto& store = sx::webserver::AdminEnrollmentStore::instance();
    const auto issued = store.issue("security-admin", 1000, 60);
    ASSERT_TRUE(issued);
    auto reservation = store.reserve(issued->token, 1001);
    ASSERT_TRUE(reservation);

    store.clear();

    EXPECT_FALSE(reservation->commit());
    EXPECT_EQ(store.size(1001), 0U);
}

TEST_F(AdminEnrollmentStoreTest, RejectsInvalidNamesMalformedTokensAndExpiry) {
    auto& store = sx::webserver::AdminEnrollmentStore::instance();
    EXPECT_FALSE(store.issue("", 1000, 60));
    EXPECT_FALSE(store.issue("administrator with spaces", 1000, 60));
    EXPECT_FALSE(store.issue("admin", 1000, 601));

    const auto issued = store.issue("admin@example.test", 1000, 60);
    ASSERT_TRUE(issued);
    EXPECT_FALSE(store.consume(std::string(64, 'G'), 1001));
    EXPECT_FALSE(store.consume("short", 1001));
    EXPECT_FALSE(store.consume(issued->token, 1060));
    EXPECT_EQ(store.size(1060), 0U);
}

TEST_F(AdminEnrollmentStoreTest, BoundsOutstandingCapabilitiesAndPrunesExpiredOnIssue) {
    auto& store = sx::webserver::AdminEnrollmentStore::instance();
    for(std::size_t index = 0; index < sx::webserver::AdminEnrollmentStore::capacity; ++index) {
        EXPECT_TRUE(store.issue("admin-" + std::to_string(index), 1000, 60));
    }
    EXPECT_FALSE(store.issue("overflow", 1000, 60));
    EXPECT_EQ(store.size(1000), sx::webserver::AdminEnrollmentStore::capacity);
    EXPECT_TRUE(store.issue("after-expiry", 1060, 60));
    EXPECT_EQ(store.size(1060), 1U);
}

TEST(WebhookOverrideLeaseTest, OwnerCanRenewAndAnotherOwnerCannotReplace) {
    WebhookOverrideLease lease;
    auto acquired = lease.acquire_or_renew("http://first", false, 60, {}, "owner-a", 1000);
    EXPECT_EQ(acquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(acquired.lease_id, "owner-a");
    EXPECT_EQ(acquired.expires_at, 1060);

    auto conflict = lease.acquire_or_renew("http://second", true, 60, {}, "owner-b", 1001);
    EXPECT_EQ(conflict.outcome, WebhookOverrideLease::Outcome::conflict);
    EXPECT_EQ(lease.target(1001).url, "http://first");

    auto renewed = lease.acquire_or_renew("http://renewed", true, 30, "owner-a", {}, 1020);
    EXPECT_EQ(renewed.outcome, WebhookOverrideLease::Outcome::renewed);
    EXPECT_EQ(renewed.expires_at, 1050);
    EXPECT_EQ(lease.target(1020).url, "http://renewed");
}

TEST(WebhookOverrideLeaseTest, ExpiryAllowsNewOwnerAndReleaseChecksOwnership) {
    WebhookOverrideLease lease;
    lease.acquire_or_renew("http://first", true, 10, {}, "owner-a", 1000);

    auto acquired = lease.acquire_or_renew("http://second", false, 999, {}, "owner-b", 1010);
    EXPECT_EQ(acquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(acquired.expires_at, 1310); // TTL is capped at five minutes.

    EXPECT_EQ(lease.release("owner-a", 1011).outcome, WebhookOverrideLease::Outcome::conflict);
    EXPECT_TRUE(lease.target(1011).active);
    EXPECT_EQ(lease.release("owner-b", 1011).outcome, WebhookOverrideLease::Outcome::released);
    EXPECT_FALSE(lease.target(1011).active);

    lease.acquire_or_renew("http://third", true, 10, {}, "owner-c", 2000);
    auto reacquired = lease.acquire_or_renew("http://fourth", true, 10, "owner-c", "owner-d", 2010);
    EXPECT_EQ(reacquired.outcome, WebhookOverrideLease::Outcome::acquired);
    EXPECT_EQ(reacquired.lease_id, "owner-d");
}

TEST(WebhookOverrideLeaseTest, RejectsIncompleteAcquisitionAndClampsShortTtl) {
    WebhookOverrideLease lease;
    EXPECT_EQ(lease.release("nobody", 1000).outcome, WebhookOverrideLease::Outcome::absent);
    EXPECT_EQ(lease.acquire_or_renew({}, true, 60, {}, "owner", 1000).outcome,
              WebhookOverrideLease::Outcome::invalid);
    EXPECT_EQ(lease.acquire_or_renew("http://first", true, 1, {}, "owner", 1000).expires_at,
              1010);
}
TEST(HttpResponderTest, AccumulatesBinaryPostChunksAndBoundsTheBody) {
    unsigned calls = 0;
    std::string received;
    auto callback = [&](MHD_Connection*, std::string const&, std::string const& body) {
        ++calls;
        received = body;
        sx::webserver::Http_JsonResponseParams result;
        result.response_code = 200;
        result.response = {{"ok", true}};
        return result;
    };
    sx::webserver::Http_Responder responder("POST", "/upload", callback);

    void* state = new lmh::ConnectionState(responder);
    std::stringstream response;
    const char first[] = {'a', '\0', 'b'};
    std::size_t first_size = sizeof(first);
    auto pending = responder.createResponse(nullptr, "/upload", "POST", first,
                                            &first_size, &state, response);
    EXPECT_EQ(pending.response_code, MHD_YES);
    EXPECT_EQ(first_size, 0U);
    EXPECT_EQ(calls, 0U);

    const char second[] = {'c', 'd'};
    std::size_t second_size = sizeof(second);
    responder.createResponse(nullptr, "/upload", "POST", second,
                             &second_size, &state, response);
    EXPECT_EQ(calls, 0U);

    std::size_t complete_size = 0;
    auto complete = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(complete.response_code, 200);
    EXPECT_EQ(calls, 1U);
    EXPECT_EQ(received, std::string(first, sizeof(first)) + std::string(second, sizeof(second)));
    delete static_cast<lmh::ConnectionState*>(state);

    calls = 0;
    state = new lmh::ConnectionState(responder);
    std::string oversized(8U * 1024U * 1024U + 1U, 'x');
    std::size_t oversized_size = oversized.size();
    responder.createResponse(nullptr, "/upload", "POST", oversized.data(),
                             &oversized_size, &state, response);
    complete_size = 0;
    auto rejected = responder.createResponse(nullptr, "/upload", "POST", nullptr,
                                             &complete_size, &state, response);
    EXPECT_EQ(rejected.response_code, 413);
    EXPECT_EQ(calls, 0U);
    delete static_cast<lmh::ConnectionState*>(state);
}


TEST(HttpDaemonLifecycle, ListenerIsCloseOnExecAndCanRestart) {
    auto const before = listening_sockets();
    lmh::WebServer server(0);
    server.options().bind_loopback = true;

    server.start_daemon();
    ASSERT_TRUE(server.is_daemon_alive());
    auto first = new_listening_sockets(before);
    ASSERT_EQ(first.size(), 1U);
    EXPECT_NE(::fcntl(*first.begin(), F_GETFD) & FD_CLOEXEC, 0);

    server.stop_daemon();
    EXPECT_FALSE(server.is_daemon_alive());
    EXPECT_TRUE(new_listening_sockets(before).empty());

    server.start_daemon();
    ASSERT_TRUE(server.is_daemon_alive());
    auto second = new_listening_sockets(before);
    ASSERT_EQ(second.size(), 1U);
    EXPECT_NE(::fcntl(*second.begin(), F_GETFD) & FD_CLOEXEC, 0);
    server.stop_daemon();
}

TEST(HttpDaemonLifecycle, RepeatedEmptyErrorResponsesRemainUsable) {
    auto const before = listening_sockets();
    lmh::WebServer missing(0);
    missing.options().bind_loopback = true;
    missing.start_daemon();
    auto listener = new_listening_sockets(before);
    ASSERT_EQ(listener.size(), 1U);
    const auto missing_port = listening_port(*listener.begin());
    ASSERT_NE(missing_port, 0U);
    for(int i = 0; i < 64; ++i) EXPECT_EQ(request_status(missing_port), 404);
    missing.stop_daemon();

    lmh::WebServer forbidden(0);
    forbidden.options().bind_loopback = true;
    forbidden.options().allowed_ips = {"192.0.2.1"};
    forbidden.start_daemon();
    listener = new_listening_sockets(before);
    ASSERT_EQ(listener.size(), 1U);
    const auto forbidden_port = listening_port(*listener.begin());
    ASSERT_NE(forbidden_port, 0U);
    for(int i = 0; i < 64; ++i) EXPECT_EQ(request_status(forbidden_port), 403);
    forbidden.stop_daemon();
}


} // namespace
