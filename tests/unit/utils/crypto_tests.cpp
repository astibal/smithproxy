#include <gtest/gtest.h>

#include <utils/crypto.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

TEST(CryptoUtils, EncodesLowercaseHex) {
    std::array<unsigned char, 4> const input {0x00, 0x0f, 0xa5, 0xff};

    EXPECT_EQ(sx::crypto::hex(input.data(), input.size()), "000fa5ff");
}

TEST(CryptoUtils, HashesEmptyAndNonEmptyInput) {
    auto const empty = sx::crypto::sha256("");
    auto const abc = sx::crypto::sha256("abc");

    ASSERT_TRUE(empty);
    EXPECT_EQ(*empty, "e3b0c44298fc1c149afbf4c8996fb924"
                      "27ae41e4649b934ca495991b7852b855");
    ASSERT_TRUE(abc);
    EXPECT_EQ(*abc, "ba7816bf8f01cfea414140de5dae2223"
                    "b00361a396177a9cb410ff61f20015ad");
}

TEST(CryptoUtils, GeneratesRequestedRandomHexLength) {
    auto const value = sx::crypto::random_hex(16);

    ASSERT_TRUE(value);
    EXPECT_EQ(value->size(), 32U);
    EXPECT_TRUE(std::all_of(value->begin(), value->end(), [](unsigned char character) {
        return std::isdigit(character) || (character >= 'a' && character <= 'f');
    }));
}

TEST(CryptoUtils, RejectsEmptyRandomRequest) {
    EXPECT_FALSE(sx::crypto::random_hex(0));
}

TEST(CryptoUtils, CreatesAndVerifiesManagementPasswordVerifier) {
    const auto verifier = sx::crypto::password_verifier("correct horse battery staple");

    ASSERT_TRUE(verifier);
    EXPECT_EQ(verifier->find("$pbkdf2-sha256$600000$"), 0U);
    EXPECT_TRUE(sx::crypto::password_matches("correct horse battery staple", *verifier));
    EXPECT_FALSE(sx::crypto::password_matches("incorrect", *verifier));
}

TEST(CryptoUtils, UsesIndependentSaltForEachPasswordVerifier) {
    const auto first = sx::crypto::password_verifier("same password");
    const auto second = sx::crypto::password_verifier("same password");

    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_NE(*first, *second);
    EXPECT_TRUE(sx::crypto::password_matches("same password", *first));
    EXPECT_TRUE(sx::crypto::password_matches("same password", *second));
}

TEST(CryptoUtils, RejectsMalformedAndUnsupportedPasswordVerifiers) {
    EXPECT_FALSE(sx::crypto::password_matches("password", ""));
    EXPECT_FALSE(sx::crypto::password_matches(
        "password", "$sha256$600000$00112233445566778899aabbccddeeff$00"));
    EXPECT_FALSE(sx::crypto::password_matches(
        "password", "$pbkdf2-sha256$0$00112233445566778899aabbccddeeff$"
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
    EXPECT_FALSE(sx::crypto::password_matches(
        "password", "$pbkdf2-sha256$599999$00112233445566778899aabbccddeeff$"
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
    EXPECT_FALSE(sx::crypto::password_matches(
        "password", "$pbkdf2-sha256$600000$not-hex$"
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
}

TEST(CryptoUtils, RejectsEmptyAndUnreasonablyLargeManagementPasswords) {
    EXPECT_FALSE(sx::crypto::password_verifier(""));
    EXPECT_FALSE(sx::crypto::password_verifier(std::string(1025, 'x')));
    const auto verifier = sx::crypto::password_verifier("valid password");
    ASSERT_TRUE(verifier);
    EXPECT_FALSE(sx::crypto::password_matches("", *verifier));
    EXPECT_FALSE(sx::crypto::password_matches(std::string(1025, 'x'), *verifier));
}
