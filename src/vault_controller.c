#include "vault_controller.h"
#include "crypto_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

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

    char backup_dir[512];
    snprintf(backup_dir, sizeof(backup_dir), "%s/backups", dir_path);
    if (stat(backup_dir, &st) == -1) {
        if (mkdir(backup_dir, 0700) == -1) {
            perror("Failed to create backups directory");
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

static int write_vault_header(FILE* fp, const VaultHeader* header) {
    rewind(fp);

    if (fwrite(header, sizeof(VaultHeader), 1, fp) != 1) {
        fprintf(stderr, "Failed to write vault header\n");
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
    size_t ciphertext_max_size = plaintext_size + IV_SIZE + 64; // IV + padding

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

static int write_vault_entries(FILE* fp) {
    if (g_vault.header.entry_count == 0) {
        ftruncate(fileno(fp), sizeof(VaultHeader));
        return 0;
    }

    size_t plaintext_size = g_vault.header.entry_count * sizeof(VaultEntry);
    unsigned char* ciphertext = malloc(plaintext_size + IV_SIZE + 64);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    int cipher_len = encrypt_data((unsigned char*)g_vault.entries, plaintext_size,
                                  g_vault.key, ciphertext);
    if (cipher_len <= 0) {
        fprintf(stderr, "Encryption failed\n");
        free(ciphertext);
        return -1;
    }

    fseek(fp, sizeof(VaultHeader), SEEK_SET);
    if (fwrite(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "Failed to write encrypted data\n");
        free(ciphertext);
        return -1;
    }

    ftruncate(fileno(fp), sizeof(VaultHeader) + cipher_len);

    free(ciphertext);
    return 0;
}

