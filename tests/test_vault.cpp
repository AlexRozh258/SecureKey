#include <gtest/gtest.h>
#include <unistd.h>
#include <sys/stat.h>
extern "C" {
    #include "vault_controller.h"
    #include "crypto_engine.h"
    #include "totp_engine.h"
}

class VaultTest : public ::testing::Test {
protected:
    const char* test_vault_path = "/tmp/test_vault.dat";
    const char* test_backup_path = "/tmp/test_vault.dat.backup";
    const char* master_password = "test_master_password_123";
    const char* new_master_password = "new_master_password_456";

    void SetUp() override {
        unlink(test_vault_path);
        unlink(test_backup_path);
    }

    void TearDown() override {
        vault_cleanup();
        unlink(test_vault_path);
        unlink(test_backup_path);
    }
};


TEST_F(VaultTest, CreateNewVault) {
    int result = vault_init(master_password, test_vault_path);
    EXPECT_EQ(result, 0);

    EXPECT_TRUE(vault_exists(test_vault_path));

    struct stat st;
    stat(test_vault_path, &st);
    EXPECT_EQ(st.st_mode & 0777, 0600);

    EXPECT_EQ(vault_entry_count(), 0);
}

TEST_F(VaultTest, OpenExistingVault) {
    vault_init(master_password, test_vault_path);
    vault_cleanup();

    int result = vault_init(master_password, test_vault_path);
    EXPECT_EQ(result, 0);
}

TEST_F(VaultTest, WrongPassword) {
    vault_init(master_password, test_vault_path);

    vault_store("test_service", "test_user", "test_pass", nullptr, true);
    vault_cleanup();

    int result = vault_init("wrong_password", test_vault_path);

    EXPECT_NE(result, 0);
}


TEST_F(VaultTest, StoreAndGetEntry) {
    vault_init(master_password, test_vault_path);

    int result = vault_store("GitHub", "user@example.com", "secret_password", nullptr, true);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(vault_entry_count(), 1);

    VaultEntry entry;
    result = vault_get("GitHub", "user@example.com", &entry);
    EXPECT_EQ(result, 0);

    EXPECT_STREQ(entry.service, "GitHub");
    EXPECT_STREQ(entry.username, "user@example.com");
    EXPECT_STREQ(entry.password, "secret_password");
    EXPECT_EQ(strlen(entry.totp_secret), 0);
}

TEST_F(VaultTest, StoreEntryWithTOTP) {
    vault_init(master_password, test_vault_path);

    char totp_secret[64];
    generate_totp_secret(totp_secret, sizeof(totp_secret));

    int result = vault_store("Google", "user@gmail.com", "password123", totp_secret, true);
    EXPECT_EQ(result, 0);

    VaultEntry entry;
    vault_get("Google", "user@gmail.com", &entry);

    EXPECT_STREQ(entry.service, "Google");
    EXPECT_STREQ(entry.username, "user@gmail.com");
    EXPECT_STREQ(entry.password, "password123");
    EXPECT_STREQ(entry.totp_secret, totp_secret);

    uint32_t code = generate_totp(entry.totp_secret);
    EXPECT_GT(code, 0);
    EXPECT_LE(code, 999999);
}

TEST_F(VaultTest, UpdateExistingEntry) {
    vault_init(master_password, test_vault_path);

    vault_store("Service", "user", "old_password", nullptr, true);
    EXPECT_EQ(vault_entry_count(), 1);

    vault_store("Service", "user", "new_password", nullptr, true);
    EXPECT_EQ(vault_entry_count(), 1); 

    VaultEntry entry;
    vault_get("Service", "user", &entry);
    EXPECT_STREQ(entry.password, "new_password");
}

TEST_F(VaultTest, StoreMultipleEntries) {
    vault_init(master_password, test_vault_path);

    vault_store("GitHub", "user1", "pass1", nullptr, true);
    vault_store("Gmail", "user2", "pass2", nullptr, true);
    vault_store("Facebook", "user3", "pass3", nullptr, true);

    EXPECT_EQ(vault_entry_count(), 3);

    VaultEntry entry;

    EXPECT_EQ(vault_get("GitHub", "user1", &entry), 0);
    EXPECT_STREQ(entry.password, "pass1");

    EXPECT_EQ(vault_get("Gmail", "user2", &entry), 0);
    EXPECT_STREQ(entry.password, "pass2");

    EXPECT_EQ(vault_get("Facebook", "user3", &entry), 0);
    EXPECT_STREQ(entry.password, "pass3");
}

TEST_F(VaultTest, GetNonExistentEntry) {
    vault_init(master_password, test_vault_path);

    VaultEntry entry;
    int result = vault_get("NonExistent", "user", &entry);

    EXPECT_NE(result, 0); 
}

TEST_F(VaultTest, RemoveEntry) {
    vault_init(master_password, test_vault_path);

    vault_store("Service1", "user1", "pass1", nullptr, true);
    vault_store("Service2", "user2", "pass2", nullptr, true);
    vault_store("Service3", "user3", "pass3", nullptr, true);
    EXPECT_EQ(vault_entry_count(), 3);

    int result = vault_remove("Service2", "user2");
    EXPECT_EQ(result, 0);
    EXPECT_EQ(vault_entry_count(), 2);

    VaultEntry entry;
    EXPECT_NE(vault_get("Service2", "user2", &entry), 0);

    EXPECT_EQ(vault_get("Service1", "user1", &entry), 0);
    EXPECT_EQ(vault_get("Service3", "user3", &entry), 0);
}

TEST_F(VaultTest, RemoveAllEntries) {
    vault_init(master_password, test_vault_path);

    vault_store("Service1", "user1", "pass1", nullptr, true);
    vault_store("Service2", "user2", "pass2", nullptr, true);

    vault_remove("Service1", "user1");
    vault_remove("Service2", "user2");

    EXPECT_EQ(vault_entry_count(), 0);
}

TEST_F(VaultTest, RemoveNonExistentEntry) {
    vault_init(master_password, test_vault_path);

    int result = vault_remove("NonExistent", "user");
    EXPECT_NE(result, 0);
}


TEST_F(VaultTest, DataPersistence) {
    vault_init(master_password, test_vault_path);
    vault_store("Persistent", "user", "password123", nullptr, true);
    vault_cleanup();

    vault_init(master_password, test_vault_path);

    EXPECT_EQ(vault_entry_count(), 1);

    VaultEntry entry;
    vault_get("Persistent", "user", &entry);
    EXPECT_STREQ(entry.password, "password123");
}

TEST_F(VaultTest, PersistenceWithMultipleEntries) {
    vault_init(master_password, test_vault_path);

    vault_store("Service1", "user1", "pass1", nullptr, true);
    vault_store("Service2", "user2", "pass2", nullptr, true);
    vault_store("Service3", "user3", "pass3", nullptr, true);

    vault_cleanup();

    vault_init(master_password, test_vault_path);

    EXPECT_EQ(vault_entry_count(), 3);

    VaultEntry entry;
    vault_get("Service1", "user1", &entry);
    EXPECT_STREQ(entry.password, "pass1");

    vault_get("Service2", "user2", &entry);
    EXPECT_STREQ(entry.password, "pass2");

    vault_get("Service3", "user3", &entry);
    EXPECT_STREQ(entry.password, "pass3");
}

TEST_F(VaultTest, BackupVault) {
    vault_init(master_password, test_vault_path);
    vault_store("Service", "user", "password", nullptr, true);

    int result = vault_backup(test_vault_path);
    EXPECT_EQ(result, 0);

    EXPECT_TRUE(vault_exists(test_backup_path));
}

TEST_F(VaultTest, RestoreFromBackup) {
    vault_init(master_password, test_vault_path);
    vault_store("Original", "user", "original_password", nullptr, true);
    vault_backup(test_vault_path);

    vault_store("Modified", "user2", "new_password", nullptr, true);
    vault_cleanup();

    int result = vault_restore(test_backup_path, test_vault_path);
    EXPECT_EQ(result, 0);

    vault_init(master_password, test_vault_path);
    EXPECT_EQ(vault_entry_count(), 1);

    VaultEntry entry;
    vault_get("Original", "user", &entry);
    EXPECT_STREQ(entry.password, "original_password");
}

TEST_F(VaultTest, AutoBackupOnModification) {
    vault_init(master_password, test_vault_path);

    unlink(test_backup_path);

    vault_store("Service", "user", "password", nullptr, true);

    EXPECT_TRUE(vault_exists(test_backup_path));
}


TEST_F(VaultTest, ChangeMasterPassword) {
    vault_init(master_password, test_vault_path);
    vault_store("Service", "user", "password", nullptr, true);

    int result = vault_change_master_password(master_password, new_master_password);
    EXPECT_EQ(result, 0);

    vault_cleanup();

    result = vault_init(new_master_password, test_vault_path);
    EXPECT_EQ(result, 0);

    VaultEntry entry;
    vault_get("Service", "user", &entry);
    EXPECT_STREQ(entry.password, "password");
}

TEST_F(VaultTest, ChangePasswordWrongOldPassword) {
    vault_init(master_password, test_vault_path);

    int result = vault_change_master_password("wrong_password", new_master_password);
    EXPECT_NE(result, 0);
}

TEST_F(VaultTest, ChangePasswordPreservesData) {
    vault_init(master_password, test_vault_path);

    vault_store("Service1", "user1", "pass1", nullptr, true);
    vault_store("Service2", "user2", "pass2", nullptr, true);
    vault_store("Service3", "user3", "pass3", nullptr, true);

    vault_change_master_password(master_password, new_master_password);
    vault_cleanup();

    vault_init(new_master_password, test_vault_path);

    EXPECT_EQ(vault_entry_count(), 3);

    VaultEntry entry;
    vault_get("Service1", "user1", &entry);
    EXPECT_STREQ(entry.password, "pass1");
}

TEST_F(VaultTest, ChangePasswordRequiresOpenVault) {
    vault_init(master_password, test_vault_path);
    vault_store("Service", "user", "password", nullptr, true);
    vault_cleanup();

    int result = vault_change_master_password(master_password, new_master_password);
    EXPECT_NE(result, 0) << "Change password should fail when vault is not open";

    vault_init(master_password, test_vault_path);
    result = vault_change_master_password(master_password, new_master_password);
    EXPECT_EQ(result, 0) << "Change password should succeed when vault is open";
}

TEST_F(VaultTest, FilePermissions) {
    vault_init(master_password, test_vault_path);

    struct stat st;
    stat(test_vault_path, &st);

    EXPECT_EQ(st.st_mode & 0777, 0600);
}

TEST_F(VaultTest, EncryptionWorks) {
    vault_init(master_password, test_vault_path);
    vault_store("Secret", "user", "very_secret_password", nullptr, true);
    vault_cleanup();

    FILE* fp = fopen(test_vault_path, "rb");
    ASSERT_NE(fp, nullptr);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* content = new char[size];
    fread(content, 1, size, fp);
    fclose(fp);

    EXPECT_EQ(strstr(content, "very_secret_password"), nullptr);

    delete[] content;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
