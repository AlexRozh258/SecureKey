#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

extern "C" {
    #include "arg_parse.h"
    #include "crypto_engine.h"
    #include "vault_controller.h"
    #include "totp_engine.h"
    #include "utilities.h"
}

class GlobalIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto_init();
        snprintf(vault_path, sizeof(vault_path), "/tmp/test_vault_%d.dat", getpid());
        master_password = "TestMasterPassword123!";
    }

    void TearDown() override {
        vault_cleanup();
        crypto_cleanup();
        remove(vault_path);

        char backup_path[512];
        snprintf(backup_path, sizeof(backup_path), "%s.backup", vault_path);
        remove(backup_path);
    }

    char vault_path[256];
    const char* master_password;
};

TEST_F(GlobalIntegrationTest, PasswordStrengthWeak) {
    int score = check_password_strength("abc");
    EXPECT_LT(score, 4) << "Password 'abc' should be weak";
}

TEST_F(GlobalIntegrationTest, PasswordStrengthModerate) {
    int score = check_password_strength("abcd1234");
    EXPECT_GE(score, 3) << "Password with letters and digits should be moderate or better";
}

TEST_F(GlobalIntegrationTest, PasswordStrengthStrong) {
    int score = check_password_strength("MySecurePass123!");
    EXPECT_GE(score, 6) << "Password with variety and good length should be strong";
}

TEST_F(GlobalIntegrationTest, PasswordStrengthEmpty) {
    int score = check_password_strength("");
    EXPECT_EQ(score, -1) << "Empty password should return error";
}

TEST_F(GlobalIntegrationTest, PasswordStrengthNull) {
    int score = check_password_strength(NULL);
    EXPECT_EQ(score, -1) << "NULL password should return error";
}

TEST_F(GlobalIntegrationTest, GeneratePasswordValid) {
    char password[65];
    int result = generate_random_password(password, sizeof(password), 16);

    EXPECT_EQ(result, 0) << "Password generation should succeed";
    EXPECT_EQ(strlen(password), 16) << "Generated password should have requested length";

    int has_lower = 0, has_upper = 0, has_digit = 0;
    for (size_t i = 0; i < strlen(password); i++) {
        if (password[i] >= 'a' && password[i] <= 'z') has_lower = 1;
        if (password[i] >= 'A' && password[i] <= 'Z') has_upper = 1;
        if (password[i] >= '0' && password[i] <= '9') has_digit = 1;
    }

    EXPECT_GT(has_lower + has_upper + has_digit, 0) << "Password should have character variety";
}

TEST_F(GlobalIntegrationTest, GeneratePasswordDifferentLengths) {
    char password1[65], password2[65];

    EXPECT_EQ(generate_random_password(password1, sizeof(password1), 8), 0);
    EXPECT_EQ(strlen(password1), 8);

    EXPECT_EQ(generate_random_password(password2, sizeof(password2), 32), 0);
    EXPECT_EQ(strlen(password2), 32);
}

TEST_F(GlobalIntegrationTest, GeneratePasswordInvalidLength) {
    char password[65];

    EXPECT_NE(generate_random_password(password, sizeof(password), 5), 0)
        << "Should fail for length < 8";
    EXPECT_NE(generate_random_password(password, sizeof(password), 100), 0)
        << "Should fail for length > 64";
}

TEST_F(GlobalIntegrationTest, GeneratePasswordNullBuffer) {
    EXPECT_NE(generate_random_password(NULL, 65, 16), 0)
        << "Should fail with NULL buffer";
}

TEST_F(GlobalIntegrationTest, CompleteVaultWorkflow) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0)
        << "Vault initialization should succeed";

    ASSERT_EQ(vault_store("GitHub", "user@example.com", "GithubPass123", NULL, false), 0);
    ASSERT_EQ(vault_store("Gmail", "user@gmail.com", "GmailPass456", "JBSWY3DPEHPK3PXP", false), 0);
    ASSERT_EQ(vault_store("AWS", "admin", "AwsSecure789!", NULL, false), 0);

    EXPECT_EQ(vault_entry_count(), 3) << "Should have 3 entries";

    VaultEntry entry;
    ASSERT_EQ(vault_get("GitHub", "user@example.com", &entry), 0);
    EXPECT_STREQ(entry.password, "GithubPass123");
    EXPECT_STREQ(entry.service, "GitHub");

    ASSERT_EQ(vault_get("Gmail", "user@gmail.com", &entry), 0);
    EXPECT_STREQ(entry.password, "GmailPass456");
    EXPECT_STREQ(entry.totp_secret, "JBSWY3DPEHPK3PXP");

    ASSERT_EQ(vault_store("GitHub", "user@example.com", "NewGithubPass999", NULL, true), 0);
    ASSERT_EQ(vault_get("GitHub", "user@example.com", &entry), 0);
    EXPECT_STREQ(entry.password, "NewGithubPass999");

    ASSERT_EQ(vault_remove("AWS", "admin"), 0);
    EXPECT_EQ(vault_entry_count(), 2) << "Should have 2 entries after removal";

    vault_cleanup();
    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    EXPECT_EQ(vault_entry_count(), 2) << "Entries should persist after closing and reopening";
    ASSERT_EQ(vault_get("GitHub", "user@example.com", &entry), 0);
    EXPECT_STREQ(entry.password, "NewGithubPass999");
}

TEST_F(GlobalIntegrationTest, VaultWithTOTPIntegration) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    char totp_secret[64];
    ASSERT_EQ(generate_totp_secret(totp_secret, sizeof(totp_secret)), 0);

    ASSERT_EQ(vault_store("Google", "user@google.com", "GooglePass123", totp_secret, false), 0);

    VaultEntry entry;
    ASSERT_EQ(vault_get("Google", "user@google.com", &entry), 0);
    EXPECT_STREQ(entry.totp_secret, totp_secret);

    uint32_t code = generate_totp(entry.totp_secret);
    EXPECT_EQ(validate_totp(entry.totp_secret, code), 0)
        << "Generated TOTP code should validate";
}

TEST_F(GlobalIntegrationTest, MultipleVaultOperationsWithCrypto) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    const char* services[] = {"Service1", "Service2", "Service3", "Service4"};
    const char* passwords[] = {"weak", "Moderate1", "VeryStrong123!", "Ultra$ecure2024!@#"};

    for (int i = 0; i < 4; i++) {
        char username[64];
        snprintf(username, sizeof(username), "user%d", i);
        ASSERT_EQ(vault_store(services[i], username, passwords[i], NULL, false), 0)
            << "Failed to store entry " << i;
    }

    for (int i = 0; i < 4; i++) {
        char username[64];
        snprintf(username, sizeof(username), "user%d", i);

        VaultEntry entry;
        ASSERT_EQ(vault_get(services[i], username, &entry), 0);
        EXPECT_STREQ(entry.password, passwords[i]) << "Password mismatch for entry " << i;

        int strength = check_password_strength(entry.password);
        EXPECT_GE(strength, 0) << "Password strength check should succeed";
    }
}

TEST_F(GlobalIntegrationTest, VaultBackupAndRestore) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);
    ASSERT_EQ(vault_store("Original", "user1", "Password1", NULL, false), 0);
    ASSERT_EQ(vault_store("Data", "user2", "Password2", NULL, false), 0);

    ASSERT_EQ(vault_backup(vault_path), 0) << "Backup should succeed";

    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.backup", vault_path);
    FILE* backup_file = fopen(backup_path, "r");
    ASSERT_NE(backup_file, nullptr) << "Backup file should exist";
    fclose(backup_file);

    vault_cleanup();

    char temp_vault[512];
    snprintf(temp_vault, sizeof(temp_vault), "/tmp/test_vault_restored_%d.dat", getpid());

    ASSERT_EQ(vault_restore(backup_path, temp_vault), 0) << "Restore should succeed";
    ASSERT_EQ(vault_init(master_password, temp_vault), 0) << "Opening restored vault should succeed";

    EXPECT_EQ(vault_entry_count(), 2) << "Restored vault should have 2 entries";
    VaultEntry entry;
    ASSERT_EQ(vault_get("Original", "user1", &entry), 0);
    EXPECT_STREQ(entry.password, "Password1");
    ASSERT_EQ(vault_get("Data", "user2", &entry), 0);
    EXPECT_STREQ(entry.password, "Password2");

    vault_cleanup();
    remove(temp_vault);
}

TEST_F(GlobalIntegrationTest, ChangeMasterPasswordIntegration) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);
    ASSERT_EQ(vault_store("Service1", "user1", "Pass1", NULL, false), 0);
    ASSERT_EQ(vault_store("Service2", "user2", "Pass2", "JBSWY3DPEHPK3PXP", false), 0);

    const char* new_password = "NewMasterPass456!";
    ASSERT_EQ(vault_change_master_password(master_password, new_password), 0)
        << "Password change should succeed";

    vault_cleanup();
    ASSERT_NE(vault_init(master_password, vault_path), 0)
        << "Old password should not work";

    vault_cleanup();
    ASSERT_EQ(vault_init(new_password, vault_path), 0)
        << "New password should work";

    VaultEntry entry;
    ASSERT_EQ(vault_get("Service1", "user1", &entry), 0);
    EXPECT_STREQ(entry.password, "Pass1");

    ASSERT_EQ(vault_get("Service2", "user2", &entry), 0);
    EXPECT_STREQ(entry.password, "Pass2");
    EXPECT_STREQ(entry.totp_secret, "JBSWY3DPEHPK3PXP");
}

TEST_F(GlobalIntegrationTest, ConcurrentPasswordGenerationAndStorage) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    for (int i = 0; i < 10; i++) {
        char password[65];
        char service[64], username[64];

        snprintf(service, sizeof(service), "Service%d", i);
        snprintf(username, sizeof(username), "user%d", i);

        ASSERT_EQ(generate_random_password(password, sizeof(password), 12 + i), 0)
            << "Password generation failed for iteration " << i;

        ASSERT_EQ(vault_store(service, username, password, NULL, false), 0)
            << "Storage failed for iteration " << i;

        VaultEntry entry;
        ASSERT_EQ(vault_get(service, username, &entry), 0);
        EXPECT_STREQ(entry.password, password);
    }

    EXPECT_EQ(vault_entry_count(), 10);
}

TEST_F(GlobalIntegrationTest, PasswordStrengthAndVaultStorage) {
    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    struct {
        const char* password;
        int min_expected_score;
    } test_cases[] = {
        {"weak", 1},
        {"Moderate1", 3},
        {"Strong123!", 5},
        {"VeryStrong123!@#ABC", 6}
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        char service[64];
        snprintf(service, sizeof(service), "Service%zu", i);

        int strength = check_password_strength(test_cases[i].password);
        EXPECT_GE(strength, test_cases[i].min_expected_score)
            << "Password strength mismatch for: " << test_cases[i].password;

        ASSERT_EQ(vault_store(service, "user", test_cases[i].password, NULL, false), 0);

        VaultEntry entry;
        ASSERT_EQ(vault_get(service, "user", &entry), 0);
        EXPECT_STREQ(entry.password, test_cases[i].password);

        int strength_after = check_password_strength(entry.password);
        EXPECT_EQ(strength, strength_after) << "Strength should not change after storage";
    }
}

TEST_F(GlobalIntegrationTest, ArgumentParsingIntegration) {

    const char* store_args[] = {"securekey", "store", "-s", "github", "-u", "user@test.com"};
    arguments_t args;
    EXPECT_EQ(parse_arguments(6, (char**)store_args, &args), 0);
    EXPECT_EQ(args.command, CMD_STORE);
    EXPECT_STREQ(args.service, "github");
    EXPECT_STREQ(args.username, "user@test.com");

    const char* get_args[] = {"securekey", "get", "-s", "gmail", "-u", "test@gmail.com", "--show"};
    EXPECT_EQ(parse_arguments(7, (char**)get_args, &args), 0);
    EXPECT_EQ(args.command, CMD_RETRIEVE);
    EXPECT_EQ(args.show_password, 1);

    const char* gen_args[] = {"securekey", "generate", "-l", "20", "--show"};
    EXPECT_EQ(parse_arguments(5, (char**)gen_args, &args), 0);
    EXPECT_EQ(args.command, CMD_GENERATE);
    EXPECT_EQ(args.password_length, 20);

    const char* check_args[] = {"securekey", "check", "-p", "TestPass123"};
    EXPECT_EQ(parse_arguments(4, (char**)check_args, &args), 0);
    EXPECT_EQ(args.command, CMD_CHECK);
    EXPECT_STREQ(args.password, "TestPass123");
}

TEST_F(GlobalIntegrationTest, FullSystemIntegration) {

    char generated_password[65];
    ASSERT_EQ(generate_random_password(generated_password, sizeof(generated_password), 20), 0);

    int strength = check_password_strength(generated_password);
    EXPECT_GT(strength, 4) << "Generated 20-char password should be strong";

    ASSERT_EQ(vault_init(master_password, vault_path), 0);

    char totp_secret[64];
    ASSERT_EQ(generate_totp_secret(totp_secret, sizeof(totp_secret)), 0);

    ASSERT_EQ(vault_store("CriticalService", "admin@company.com",
                         generated_password, totp_secret, false), 0);

    VaultEntry entry;
    ASSERT_EQ(vault_get("CriticalService", "admin@company.com", &entry), 0);
    EXPECT_STREQ(entry.password, generated_password);
    EXPECT_STREQ(entry.totp_secret, totp_secret);

    uint32_t totp_code = generate_totp(totp_secret);
    EXPECT_EQ(validate_totp(totp_secret, totp_code), 0);

    ASSERT_EQ(vault_backup(vault_path), 0);

    vault_cleanup();
    ASSERT_EQ(vault_init(master_password, vault_path), 0);
    ASSERT_EQ(vault_get("CriticalService", "admin@company.com", &entry), 0);
    EXPECT_STREQ(entry.password, generated_password);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
