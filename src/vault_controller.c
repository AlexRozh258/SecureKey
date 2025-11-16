#include "vault_controller.h"
#include "crypto_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/rand.h>

static VaultState g_vault = {
    .vault_path = {0},
    .key = {0},
    .header = {0},
    .entries = NULL,
    .is_open = false,
    .auto_backup = true
};

static void expand_path(const char* path, char* expanded, size_t size) {
    if (path[0] == '~') {
        const char* home = getenv("HOME");
        if (home) {
            snprintf(expanded, size, "%s%s", home, path + 1);
            return;
        }
    }
    strncpy(expanded, path, size - 1);
    expanded[size - 1] = '\0';
}

int vault_ensure_directory(void) {
    char dir_path[512];
    expand_path("~/.securekey", dir_path, sizeof(dir_path));

    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        if (mkdir(dir_path, 0700) == -1) {
            perror("Failed to create .securekey directory");
            return -1;
        }
    }

    return 0;
}

const char* vault_get_default_path(void) {
    static char path[512];
    expand_path(VAULT_DEFAULT_PATH, path, sizeof(path));
    return path;
}

bool vault_exists(const char* vault_path) {
    char expanded_path[512];
    expand_path(vault_path, expanded_path, sizeof(expanded_path));
    return access(expanded_path, F_OK) == 0;
}

size_t vault_entry_count(void) {
    if (!g_vault.is_open) {
        return 0;
    }
    return g_vault.header.entry_count;
}

int vault_find_entry(const char* service, const char* username) {
    if (!g_vault.is_open || !g_vault.entries) {
        return -1;
    }

    for (uint32_t i = 0; i < g_vault.header.entry_count; i++) {
        if (strcmp(g_vault.entries[i].service, service) == 0 &&
            strcmp(g_vault.entries[i].username, username) == 0) {
            return (int)i;
        }
    }

    return -1;
}

// Helper: Copy file (used for backup/restore)
static int copy_file(const char* src_path, const char* dst_path) {
    FILE* src = fopen(src_path, "rb");
    if (!src) {
        return -1;
    }

    FILE* dst = fopen(dst_path, "wb");
    if (!dst) {
        fclose(src);
        return -1;
    }

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            fclose(src);
            fclose(dst);
            return -1;
        }
    }

    fclose(src);
    fclose(dst);
    chmod(dst_path, 0600);

    return 0;
}

// Helper: Save vault to file (combines header + entries write)
static int save_vault(void) {
    FILE* fp = fopen(g_vault.vault_path, "rb+");
    if (!fp) {
        fprintf(stderr, "Failed to open vault for writing\n");
        return -1;
    }

    // Write header
    rewind(fp);
    if (fwrite(&g_vault.header, sizeof(VaultHeader), 1, fp) != 1) {
        fprintf(stderr, "Failed to write vault header\n");
        fclose(fp);
        return -1;
    }

    // Write encrypted entries
    if (g_vault.header.entry_count == 0) {
        ftruncate(fileno(fp), sizeof(VaultHeader));
        fclose(fp);
        return 0;
    }

    size_t plaintext_size = g_vault.header.entry_count * sizeof(VaultEntry);
    unsigned char* ciphertext = malloc(plaintext_size + IV_SIZE + 64);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    int cipher_len = encrypt_data((unsigned char*)g_vault.entries, plaintext_size,
                                  g_vault.key, ciphertext);
    if (cipher_len <= 0) {
        fprintf(stderr, "Encryption failed\n");
        free(ciphertext);
        fclose(fp);
        return -1;
    }

    fseek(fp, sizeof(VaultHeader), SEEK_SET);
    if (fwrite(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "Failed to write encrypted data\n");
        free(ciphertext);
        fclose(fp);
        return -1;
    }

    ftruncate(fileno(fp), sizeof(VaultHeader) + cipher_len);
    free(ciphertext);
    fclose(fp);

    return 0;
}


static int read_vault_header(FILE* fp, VaultHeader* header) {
    rewind(fp);

    if (fread(header, sizeof(VaultHeader), 1, fp) != 1) {
        fprintf(stderr, "Failed to read vault header\n");
        return -1;
    }

    if (memcmp(header->magic, VAULT_MAGIC, 4) != 0) {
        fprintf(stderr, "Invalid vault file format\n");
        return -1;
    }

    if (header->version != VAULT_VERSION) {
        fprintf(stderr, "Unsupported vault version: %u\n", header->version);
        return -1;
    }

    return 0;
}

static int read_vault_entries(FILE* fp) {
    if (g_vault.header.entry_count == 0) {
        g_vault.entries = NULL;
        return 0;
    }

    size_t plaintext_size = g_vault.header.entry_count * sizeof(VaultEntry);
    size_t ciphertext_max_size = plaintext_size + IV_SIZE + 64;

    unsigned char* ciphertext = malloc(ciphertext_max_size);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    fseek(fp, sizeof(VaultHeader), SEEK_SET);
    size_t ciphertext_size = fread(ciphertext, 1, ciphertext_max_size, fp);
    if (ciphertext_size == 0) {
        fprintf(stderr, "Failed to read encrypted data\n");
        free(ciphertext);
        return -1;
    }

    unsigned char* plaintext = malloc(plaintext_size);
    if (!plaintext) {
        fprintf(stderr, "Memory allocation failed\n");
        free(ciphertext);
        return -1;
    }

    int decrypted_len = decrypt_data(ciphertext, ciphertext_size,
                                     g_vault.key, plaintext);
    free(ciphertext);

    if (decrypted_len < 0 || (size_t)decrypted_len != plaintext_size) {
        fprintf(stderr, "Decryption failed or wrong password\n");
        free(plaintext);
        return -1;
    }

    g_vault.entries = (VaultEntry*)plaintext;
    return 0;
}

int vault_init(const char* master_password, const char* vault_path) {
    if (!master_password) {
        fprintf(stderr, "Master password is required\n");
        return -1;
    }

    if (g_vault.is_open) {
        vault_cleanup();
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto engine\n");
        return -1;
    }

    if (vault_ensure_directory() != 0) {
        return -1;
    }

    const char* path = vault_path ? vault_path : vault_get_default_path();
    expand_path(path, g_vault.vault_path, sizeof(g_vault.vault_path));

    FILE* fp;
    bool is_new_vault = !vault_exists(g_vault.vault_path);

    if (is_new_vault) {
        fp = fopen(g_vault.vault_path, "wb+");
        if (!fp) {
            fprintf(stderr, "Failed to create vault file: %s\n", strerror(errno));
            return -1;
        }

        chmod(g_vault.vault_path, 0600);

        memcpy(g_vault.header.magic, VAULT_MAGIC, 4);
        g_vault.header.version = VAULT_VERSION;
        g_vault.header.entry_count = 0;

        if (RAND_bytes(g_vault.header.salt, SALT_SIZE) != 1) {
            fprintf(stderr, "Failed to generate salt\n");
            fclose(fp);
            return -1;
        }

        rewind(fp);
        if (fwrite(&g_vault.header, sizeof(VaultHeader), 1, fp) != 1) {
            fprintf(stderr, "Failed to write vault header\n");
            fclose(fp);
            return -1;
        }

        printf("Created new vault: %s\n", g_vault.vault_path);

    } else {
        fp = fopen(g_vault.vault_path, "rb+");
        if (!fp) {
            fprintf(stderr, "Failed to open vault file: %s\n", strerror(errno));
            return -1;
        }

        if (read_vault_header(fp, &g_vault.header) != 0) {
            fclose(fp);
            return -1;
        }
    }

    if (derive_key(master_password, g_vault.key) != 0) {
        fprintf(stderr, "Failed to derive encryption key\n");
        fclose(fp);
        return -1;
    }

    if (!is_new_vault && g_vault.header.entry_count > 0) {
        if (read_vault_entries(fp) != 0) {
            fclose(fp);
            secure_cleanup(g_vault.key, sizeof(g_vault.key));
            return -1;
        }
    }

    fclose(fp);
    g_vault.is_open = true;

    return 0;
}

int vault_store(const char* service, const char* username,
                const char* password, const char* totp_secret, bool force) {
    if (!g_vault.is_open) {
        fprintf(stderr, "Vault is not open\n");
        return -1;
    }

    if (!service || !username || !password) {
        fprintf(stderr, "Service, username and password are required\n");
        return -1;
    }

    int existing_index = vault_find_entry(service, username);

    if (existing_index >= 0 && !force) {
        printf("Entry for '%s' (%s) already exists.\n", service, username);
        printf("Overwrite? (y/n): ");
        char answer;
        scanf(" %c", &answer);
        if (answer != 'y' && answer != 'Y') {
            printf("Cancelled.\n");
            return -1;
        }
    }

    if (g_vault.auto_backup) {
        vault_backup(g_vault.vault_path);
    }

    VaultEntry new_entry = {0};
    strncpy(new_entry.service, service, VAULT_SERVICE_LEN - 1);
    strncpy(new_entry.username, username, VAULT_USERNAME_LEN - 1);
    strncpy(new_entry.password, password, VAULT_PASSWORD_LEN - 1);
    if (totp_secret) {
        strncpy(new_entry.totp_secret, totp_secret, VAULT_TOTP_LEN - 1);
    }

    if (existing_index >= 0) {
        g_vault.entries[existing_index] = new_entry;
    } else {
        VaultEntry* new_entries = realloc(g_vault.entries,
                                          (g_vault.header.entry_count + 1) * sizeof(VaultEntry));
        if (!new_entries) {
            fprintf(stderr, "Memory allocation failed\n");
            return -1;
        }
        g_vault.entries = new_entries;
        g_vault.entries[g_vault.header.entry_count] = new_entry;
        g_vault.header.entry_count++;
    }

    if (save_vault() != 0) {
        return -1;
    }

    if (existing_index >= 0) {
        printf("Updated entry for '%s' (%s)\n", service, username);
    } else {
        printf("Stored entry for '%s' (%s)\n", service, username);
    }

    return 0;
}

int vault_get(const char* service, const char* username, VaultEntry* entry) {
    if (!g_vault.is_open) {
        fprintf(stderr, "Vault is not open\n");
        return -1;
    }

    if (!service || !username || !entry) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }

    int index = vault_find_entry(service, username);
    if (index < 0) {
        fprintf(stderr, "Entry not found: %s (%s)\n", service, username);
        return -1;
    }

    *entry = g_vault.entries[index];
    return 0;
}

int vault_list(void) {
    if (!g_vault.is_open) {
        fprintf(stderr, "Vault is not open\n");
        return -1;
    }

    if (g_vault.header.entry_count == 0) {
        printf("Vault is empty.\n");
        return 0;
    }

    printf("\n=== Vault Entries (%u) ===\n\n", g_vault.header.entry_count);

    for (uint32_t i = 0; i < g_vault.header.entry_count; i++) {
        printf("%3u. %-30s %-30s", i + 1,
               g_vault.entries[i].service,
               g_vault.entries[i].username);

        if (strlen(g_vault.entries[i].totp_secret) > 0) {
            printf(" [TOTP]");
        }

        printf("\n");
    }

    printf("\n");
    return 0;
}

int vault_remove(const char* service, const char* username) {
    if (!g_vault.is_open) {
        fprintf(stderr, "Vault is not open\n");
        return -1;
    }

    if (!service || !username) {
        fprintf(stderr, "Service and username are required\n");
        return -1;
    }

    int index = vault_find_entry(service, username);
    if (index < 0) {
        fprintf(stderr, "Entry not found: %s (%s)\n", service, username);
        return -1;
    }

    if (g_vault.auto_backup) {
        vault_backup(g_vault.vault_path);
    }

    for (uint32_t i = index; i < g_vault.header.entry_count - 1; i++) {
        g_vault.entries[i] = g_vault.entries[i + 1];
    }

    g_vault.header.entry_count--;

    if (g_vault.header.entry_count > 0) {
        VaultEntry* new_entries = realloc(g_vault.entries,
                                          g_vault.header.entry_count * sizeof(VaultEntry));
        if (new_entries) {
            g_vault.entries = new_entries;
        }
    } else {
        free(g_vault.entries);
        g_vault.entries = NULL;
    }

    if (save_vault() != 0) {
        return -1;
    }

    printf("Removed entry for '%s' (%s)\n", service, username);
    return 0;
}

void vault_cleanup(void) {
    if (!g_vault.is_open) {
        return;
    }

    secure_cleanup(g_vault.key, sizeof(g_vault.key));

    if (g_vault.entries) {
        secure_cleanup(g_vault.entries,
                       g_vault.header.entry_count * sizeof(VaultEntry));
        free(g_vault.entries);
        g_vault.entries = NULL;
    }

    memset(&g_vault.header, 0, sizeof(VaultHeader));
    memset(g_vault.vault_path, 0, sizeof(g_vault.vault_path));

    g_vault.is_open = false;

    crypto_cleanup();
}

int vault_backup(const char* vault_path) {
    if (!vault_path) {
        vault_path = g_vault.vault_path;
    }

    char expanded_vault[512];
    expand_path(vault_path, expanded_vault, sizeof(expanded_vault));

    if (!vault_exists(expanded_vault)) {
        fprintf(stderr, "Vault file does not exist: %s\n", expanded_vault);
        return -1;
    }

    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.backup", expanded_vault);

    if (copy_file(expanded_vault, backup_path) != 0) {
        fprintf(stderr, "Failed to create backup\n");
        return -1;
    }

    return 0;
}

int vault_restore(const char* backup_path, const char* vault_path) {
    if (!backup_path || !vault_path) {
        fprintf(stderr, "Backup path and vault path are required\n");
        return -1;
    }

    char expanded_backup[512];
    char expanded_vault[512];
    expand_path(backup_path, expanded_backup, sizeof(expanded_backup));
    expand_path(vault_path, expanded_vault, sizeof(expanded_vault));

    if (!vault_exists(expanded_backup)) {
        fprintf(stderr, "Backup file does not exist: %s\n", expanded_backup);
        return -1;
    }

    if (copy_file(expanded_backup, expanded_vault) != 0) {
        fprintf(stderr, "Failed to restore backup\n");
        return -1;
    }

    printf("Vault restored from: %s\n", expanded_backup);
    return 0;
}

int vault_change_master_password(const char* old_password, const char* new_password) {
    if (!g_vault.is_open) {
        fprintf(stderr, "Vault is not open\n");
        return -1;
    }

    if (!old_password || !new_password) {
        fprintf(stderr, "Old and new passwords are required\n");
        return -1;
    }

    unsigned char old_key[32];
    if (derive_key(old_password, old_key) != 0) {
        fprintf(stderr, "Failed to derive old key\n");
        return -1;
    }

    if (memcmp(old_key, g_vault.key, 32) != 0) {
        fprintf(stderr, "Wrong old password\n");
        secure_cleanup(old_key, sizeof(old_key));
        return -1;
    }

    secure_cleanup(old_key, sizeof(old_key));

    if (g_vault.auto_backup) {
        vault_backup(g_vault.vault_path);
    }

    if (RAND_bytes(g_vault.header.salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Failed to generate new salt\n");
        return -1;
    }

    unsigned char new_key[32];
    if (derive_key(new_password, new_key) != 0) {
        fprintf(stderr, "Failed to derive new key\n");
        return -1;
    }

    unsigned char old_vault_key[32];
    memcpy(old_vault_key, g_vault.key, 32);

    memcpy(g_vault.key, new_key, 32);
    secure_cleanup(new_key, sizeof(new_key));

    if (save_vault() != 0) {
        memcpy(g_vault.key, old_vault_key, 32);
        secure_cleanup(old_vault_key, sizeof(old_vault_key));
        return -1;
    }

    secure_cleanup(old_vault_key, sizeof(old_vault_key));

    printf("Master password changed successfully\n");
    return 0;
}

bool vault_verify_password(const char* vault_path, const char* master_password) {
    if (!vault_path || !master_password) {
        return false;
    }

    char expanded_path[512];
    expand_path(vault_path, expanded_path, sizeof(expanded_path));

    if (!vault_exists(expanded_path)) {
        return false;
    }

    FILE* fp = fopen(expanded_path, "rb");
    if (!fp) {
        return false;
    }

    VaultHeader header;
    if (read_vault_header(fp, &header) != 0) {
        fclose(fp);
        return false;
    }

    fclose(fp);

    unsigned char key[32];
    if (derive_key(master_password, key) != 0) {
        return false;
    }

    secure_cleanup(key, sizeof(key));
    return true;
}
