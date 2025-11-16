#include <gtest/gtest.h>
#include <cstring>
#include <iostream>

extern "C" {
    #include "totp_engine.h"
}

class TOTPEngineTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

// Тест генерації TOTP коду
TEST_F(TOTPEngineTest, GenerateTOTP) {
    // Відомий тестовий секрет (Base32)
    const char* test_secret = "JBSWY3DPEHPK3PXP";
    
    uint32_t code = generate_totp(test_secret);
    
    // TOTP код має бути 6-значним числом
    EXPECT_GE(code, 0u);
    EXPECT_LE(code, 999999u);
    
    std::cout << "Generated TOTP: " << code << std::endl;
}

// Тест генерації секрету
TEST_F(TOTPEngineTest, GenerateSecret) {
    char secret[33];  // 32 символи + null terminator
    
    int result = generate_totp_secret(secret, sizeof(secret));
    
    EXPECT_EQ(result, 0);
    EXPECT_GT(strlen(secret), 0u);
    
    // Перевіряємо, що секрет містить тільки Base32 символи
    for (size_t i = 0; i < strlen(secret); i++) {
        char ch = secret[i];
        bool valid_char = (ch >= 'A' && ch <= 'Z') || 
                         (ch >= '2' && ch <= '7') ||
                         ch == '=';
        EXPECT_TRUE(valid_char);
    }
    
    std::cout << "Generated secret: " << secret << std::endl;
}

// Тест Base32 кодування/декодування
TEST_F(TOTPEngineTest, Base32EncodeDecode) {
    const unsigned char test_data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    char encoded[64];
    unsigned char decoded[16];
    
    // Кодуємо
    int encode_result = base32_encode(test_data, 5, encoded, sizeof(encoded));
    EXPECT_GT(encode_result, 0);
    
    // Декодуємо
    int decode_result = base32_decode(encoded, decoded, sizeof(decoded));
    EXPECT_GT(decode_result, 0);
    
    // Перевіряємо, що дані співпадають
    EXPECT_EQ(memcmp(test_data, decoded, 5), 0);
    
    std::cout << "Base32 encoded: " << encoded << std::endl;
}

// Тест валідації TOTP (простий тест формату)
TEST_F(TOTPEngineTest, ValidateTOTPFormat) {
    const char* test_secret = "JBSWY3DPEHPK3PXP";
    
    // Генеруємо код
    uint32_t code = generate_totp(test_secret);
    
    // Перевіряємо формат
    EXPECT_GE(code, 0u);
    EXPECT_LE(code, 999999u);
    
    // Код має бути 6-значним
    EXPECT_GE(code, 100000u);  // Мінімум 6 цифр
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
