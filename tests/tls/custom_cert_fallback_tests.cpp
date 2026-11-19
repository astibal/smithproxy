#include <gtest/gtest.h>
#include <service/cfgapi/custom_cert_directory.hpp>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

class CustomCertFallback : public testing::Test {
protected:
    static void SetUpTestSuite() {
        Log::init();
        Log::get()->level(WAR);
        auto& store = SSLFactory::factory();
        store.certs_path() = "etc/certs/default/";
        store.certs_password() = "smithproxy";
        store.ca_file() = "etc/certs/default/ca-cert.pem";
        store.ca_path().clear();
        store.init();
    }

    SSLFactory& factory = SSLFactory::factory();
    fs::path root;
    std::string saved_primary;
    std::string saved_fallback;

    void SetUp() override {
        Log::init();
        Log::get()->level(WAR);
        char pattern[] = "/tmp/custom-cert-fallback-XXXXXX";
        ASSERT_NE(::mkdtemp(pattern), nullptr);
        root = pattern;
        saved_primary = factory.certs_path();
        saved_fallback = factory.custom_cert_fallback_dir();
        factory.certs_path() = (root / "primary").string();
        factory.custom_cert_fallback_dir() = (root / "external").string();
        factory.certs_password() = "smithproxy";
    }

    void TearDown() override {
        factory.cache_custom().clear();
        factory.certs_path() = saved_primary;
        factory.custom_cert_fallback_dir() = saved_fallback;
        fs::remove_all(root);
    }

    void identity(const fs::path& path, bool fullchain = true) {
        fs::create_directories(path);
        fs::copy_file("etc/certs/default/srv-key.pem", path / "key.pem",
                      fs::copy_options::overwrite_existing);
        fs::copy_file("etc/certs/default/srv-cert.pem",
                      path / (fullchain ? "fullchain.pem" : "cert.pem"),
                      fs::copy_options::overwrite_existing);
    }
};

TEST_F(CustomCertFallback, EmptyDisablesAndMissingDirectoriesAreNotCreated) {
    identity(root / "external/sni/example.test");
    factory.custom_cert_fallback_dir().clear();
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(factory.find_custom_fallback("example.test", ""));
    factory.custom_cert_fallback_dir() = (root / "absent").string();
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(fs::exists(root / "absent"));
    EXPECT_FALSE(factory.find_custom_fallback("", ""));
    EXPECT_FALSE(factory.find_custom_fallback("absent", "192.0.2.1"));
}

TEST_F(CustomCertFallback, FullchainAndSplitServerIdentitiesOnly) {
    identity(root / "external/sni/example.test");
    identity(root / "external/ip/192.0.2.1", false);
    identity(root / "external/cc-sni/client.test");
    const auto ca_file = factory.ca_file();
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_TRUE(factory.find_custom_fallback("example.test", ""));
    EXPECT_TRUE(factory.find_custom_fallback("", "192.0.2.1"));
    EXPECT_FALSE(factory.find_custom("cc-sni:client.test"));
    EXPECT_EQ(factory.ca_file(), ca_file);
    EXPECT_EQ(factory.cache_custom().size(), 2U);
    // SNI is preferred to IP inside the external source.
    auto sni = factory.find_custom_fallback("example.test", "192.0.2.1");
    auto exact = factory.find_custom("fallback:sni:example.test");
    ASSERT_TRUE(sni); ASSERT_TRUE(exact);
    EXPECT_EQ(sni->chain.cert, exact->chain.cert);
}

TEST_F(CustomCertFallback, PrimaryNamesBlockFallbackEvenWhenBroken) {
    identity(root / "external/sni/example.test");
    identity(root / "external/ip/192.0.2.1");
    identity(root / "primary/server/sni/example.test");
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_TRUE(factory.find_custom("sni:example.test"));
    EXPECT_FALSE(factory.find_custom_fallback("example.test", "192.0.2.1"));
    fs::remove_all(root / "primary/server/sni/example.test");
    fs::create_directories(root / "primary/server/ip/192.0.2.1");
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(factory.find_custom("ip:192.0.2.1"));
    EXPECT_FALSE(factory.find_custom_fallback("example.test", "192.0.2.1"));
    EXPECT_TRUE(factory.find_custom_fallback("example.test", ""));
}

TEST_F(CustomCertFallback, ReloadEvictsRemovedIdentitiesAndSessions) {
    identity(root / "external/sni/example.test");
    EXPECT_TRUE(factory.load_custom_certificates());
    auto first = factory.find_custom_fallback("example.test", "");
    ASSERT_TRUE(first);
    auto first_der = i2d_X509(first->chain.cert, nullptr);
    EXPECT_GT(first_der, 0);
    fs::remove_all(root / "external/sni/example.test");
    factory.session_cache().set("previous", new session_holder(nullptr));
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(factory.find_custom_fallback("example.test", ""));
    EXPECT_EQ(factory.session_cache().size(), 0U);
    identity(root / "external/sni/example.test");
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_TRUE(factory.find_custom_fallback("example.test", ""));
    factory.custom_cert_fallback_dir().clear();
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(factory.find_custom("fallback:sni:example.test"));
}

TEST_F(CustomCertFallback, UnreadablePrimaryNamespaceDoesNotPermitFallback) {
    identity(root / "external/sni/example.test");
    fs::create_directories(root / "primary/server");
    std::ofstream(root / "primary/server/sni") << "not a directory";
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_FALSE(factory.find_custom_fallback("example.test", ""));
}

TEST_F(CustomCertFallback, CustomOnlyCanUseExternalIdentityAndHonorsProfile) {
    identity(root / "external/sni/example.test");
    EXPECT_TRUE(factory.load_custom_certificates());
    SpoofOptions options;
    options.sni = "example.test";
    {
        SSLMitmCom connection;
        connection.factory(&factory);
        connection.opt.cert.mitm_cert_sni_search = true;
        connection.opt.cert.mitm_cert_searched_only = true;
        EXPECT_TRUE(connection.spoof_cert(nullptr, options));
        connection.use_cert_null();
    }
    {
        SSLMitmCom connection;
        connection.factory(&factory);
        connection.opt.cert.mitm_cert_sni_search = false;
        connection.opt.cert.mitm_cert_ip_search = false;
        connection.opt.cert.mitm_cert_searched_only = true;
        EXPECT_FALSE(connection.spoof_cert(nullptr, options));
    }
}

TEST_F(CustomCertFallback, ExternalPathIsAbsoluteAndOutsideManagedTree) {
    EXPECT_EQ(cfgapi_detail::custom_cert_directory(""), "");
    EXPECT_THROW(cfgapi_detail::custom_cert_directory("relative"), std::invalid_argument);
    EXPECT_THROW(cfgapi_detail::custom_cert_directory("/etc/smithproxy"), std::invalid_argument);
    EXPECT_THROW(cfgapi_detail::custom_cert_directory("/etc/smithproxy/certs"), std::invalid_argument);
    fs::create_directory_symlink("/etc/smithproxy", root / "alias");
    EXPECT_THROW(cfgapi_detail::custom_cert_directory((root / "alias/certs").string()), std::invalid_argument);
    EXPECT_EQ(cfgapi_detail::custom_cert_directory(root.string()), root.string());
    fs::create_directories(root / "valid");
    fs::create_directory_symlink(root / "valid", root / "valid-link");
    EXPECT_EQ(cfgapi_detail::custom_cert_directory((root / "valid-link").string()),
              (root / "valid-link").string());
    std::ofstream(root / "plain-file") << "not a directory";
    EXPECT_THROW(cfgapi_detail::custom_cert_directory((root / "plain-file/child").string()),
                 fs::filesystem_error);
}

class IdentityProbe : public SSLMitmCom {
public:
    X509* selected_certificate() const { return sslcom_pref_cert; }
};

TEST_F(CustomCertFallback, PrimaryIpWinsOverExternalSniAndExternalIpWorksAlone) {
    identity(root / "external/sni/example.test");
    identity(root / "external/ip/192.0.2.1");
    identity(root / "primary/server/ip/192.0.2.1");
    for (const bool primary : {true, false}) {
        if (!primary) fs::remove_all(root / "primary/server/ip/192.0.2.1");
        ASSERT_TRUE(factory.load_custom_certificates());
        auto* connection = new IdentityProbe();
        baseHostCX client(connection, "192.0.2.2", "12345");
        baseHostCX origin(new TCPCom(), "192.0.2.1", "443");
        client.peer(&origin);
        connection->opt.cert.mitm_cert_sni_search = primary;
        connection->opt.cert.mitm_cert_ip_search = true;
        connection->opt.cert.mitm_cert_searched_only = true;
        SpoofOptions options;
        options.sni = "example.test";
        EXPECT_TRUE(connection->spoof_cert(nullptr, options));
        auto expected = factory.find_custom(primary ? "ip:192.0.2.1" : "fallback:ip:192.0.2.1");
        EXPECT_TRUE(expected);
        if (expected) {
            EXPECT_EQ(connection->selected_certificate(), expected->chain.cert);
        }
        connection->use_cert_null();
        client.peer(nullptr);
    }
}

TEST_F(CustomCertFallback, RenewalLoadsNewCertificateBytes) {
    const auto directory = root / "external/sni/example.test";
    identity(directory, false);
    ASSERT_TRUE(factory.load_custom_certificates());
    auto previous = factory.find_custom_fallback("example.test", "");
    ASSERT_TRUE(previous);
    unsigned char old_digest[EVP_MAX_MD_SIZE];
    unsigned int old_length = 0;
    ASSERT_EQ(X509_digest(previous->chain.cert, EVP_sha256(), old_digest, &old_length), 1);
    fs::copy_file("etc/certs/default/cl-cert.pem", directory / "cert.pem", fs::copy_options::overwrite_existing);
    fs::copy_file("etc/certs/default/cl-key.pem", directory / "key.pem", fs::copy_options::overwrite_existing);
    ASSERT_TRUE(factory.load_custom_certificates());
    auto renewed = factory.find_custom_fallback("example.test", "");
    ASSERT_TRUE(renewed);
    unsigned char new_digest[EVP_MAX_MD_SIZE];
    unsigned int new_length = 0;
    ASSERT_EQ(X509_digest(renewed->chain.cert, EVP_sha256(), new_digest, &new_length), 1);
    EXPECT_NE(std::string(reinterpret_cast<char*>(old_digest), old_length),
              std::string(reinterpret_cast<char*>(new_digest), new_length));
}
