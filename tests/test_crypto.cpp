#include <gtest/gtest.h>
#include <cstring>

extern "C" {
    #include "crypto_engine.h"
}

class CryptoEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
};

TEST_F(CryptoEngineTest, KeyDerivation) {
    unsigned char key[32];
    const char* password = "test_password";
    
    EXPECT_EQ(derive_key(password, key), 0);
    
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (key[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
    
    secure_cleanup(key, 32);
}

TEST_F(CryptoEngineTest, EncryptionDecryption) {
    unsigned char key[32];
    const char* password = "master123";
    const char* plaintext = "Hello, SecureKey!";
    size_t text_len = std::strlen(plaintext);
    
    ASSERT_EQ(derive_key(password, key), 0);
    
    unsigned char ciphertext[256];
    int cipher_len = encrypt_data((const unsigned char*)plaintext, text_len, key, ciphertext);
    EXPECT_GT(cipher_len, 0);
    
    unsigned char decrypted[256];
    int decrypted_len = decrypt_data(ciphertext, cipher_len, key, decrypted);
    EXPECT_GT(decrypted_len, 0);
    
    EXPECT_EQ(decrypted_len, (int)text_len);
    EXPECT_EQ(std::memcmp(plaintext, decrypted, text_len), 0);
    
    secure_cleanup(key, 32);
}

TEST_F(CryptoEngineTest, WrongKeyDecryption) {
    unsigned char key1[32], key2[32];
    const char* password1 = "password1";
    const char* password2 = "password2";
    const char* plaintext = "Secret data";
    size_t plaintext_len = std::strlen(plaintext);
    
    ASSERT_EQ(derive_key(password1, key1), 0);
    ASSERT_EQ(derive_key(password2, key2), 0);
    
    unsigned char ciphertext[256];
    int cipher_len = encrypt_data((const unsigned char*)plaintext, plaintext_len, key1, ciphertext);
    ASSERT_GT(cipher_len, 0);
    
    unsigned char decrypted[256];
    int decrypted_len = decrypt_data(ciphertext, cipher_len, key2, decrypted);
    EXPECT_NE(decrypted_len, (int)plaintext_len);
    
    secure_cleanup(key1, 32);
    secure_cleanup(key2, 32);
}

TEST_F(CryptoEngineTest, EmptyData) {
    unsigned char key[32];
    const char* password = "test";
    
    ASSERT_EQ(derive_key(password, key), 0);
    
    unsigned char ciphertext[256];
    int cipher_len = encrypt_data((const unsigned char*)"", 0, key, ciphertext);
    EXPECT_GE(cipher_len, 0);
    
    unsigned char decrypted[256];
    int decrypted_len = decrypt_data(ciphertext, cipher_len, key, decrypted);
    EXPECT_EQ(decrypted_len, 0);
    
    secure_cleanup(key, 32);
}

TEST_F(CryptoEngineTest, SecureCleanup) {
    unsigned char data[32];
    for (int i = 0; i < 32; i++) {
        data[i] = i;
    }
    
    secure_cleanup(data, sizeof(data));
    
    for (size_t i = 0; i < sizeof(data); i++) {
        EXPECT_EQ(data[i], 0);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
