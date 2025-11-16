#ifndef VAULT_CONTROLLER_H
#define VAULT_CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define VAULT_MAGIC "SKEY"
#define VAULT_VERSION 1
#define VAULT_DEFAULT_PATH "~/.securekey/vault.dat"
#define VAULT_BACKUP_DIR "~/.securekey/backups"
#define VAULT_MAX_BACKUPS 5

#define VAULT_SERVICE_LEN 256
#define VAULT_USERNAME_LEN 256
#define VAULT_PASSWORD_LEN 256
#define VAULT_TOTP_LEN 64

#define SALT_SIZE 16
#define IV_SIZE 16


typedef struct {
    char service[VAULT_SERVICE_LEN];    
    char username[VAULT_USERNAME_LEN]; 
    char password[VAULT_PASSWORD_LEN]; 
    char totp_secret[VAULT_TOTP_LEN];   
} VaultEntry;

typedef struct {
    char magic[4];              
    uint32_t version;           
    unsigned char salt[SALT_SIZE];  
    uint32_t entry_count;      
} VaultHeader;

typedef struct {
    char vault_path[512];          
    unsigned char key[32];          
    VaultHeader header;           
    VaultEntry* entries;           
    bool is_open;                  
    bool auto_backup;               
} VaultState;


int vault_init(const char* master_password, const char* vault_path);

int vault_store(const char* service, const char* username,
                const char* password, const char* totp_secret, bool force);


int vault_get(const char* service, const char* username, VaultEntry* entry);


int vault_list(void);

int vault_remove(const char* service, const char* username);

void vault_cleanup(void);

int vault_change_master_password(const char* old_password,
                                  const char* new_password);

int vault_export(const char* output_path, const char* master_password);

int vault_import(const char* input_path, const char* master_password);

int vault_backup(const char* vault_path);

int vault_restore(const char* backup_path, const char* vault_path);

int vault_list_backups(const char* vault_path);

int vault_cleanup_backups(const char* vault_path, int keep_count);

bool vault_exists(const char* vault_path);

bool vault_verify_password(const char* vault_path, const char* master_password);

size_t vault_entry_count(void);

int vault_find_entry(const char* service, const char* username);

const char* vault_get_default_path(void);
int vault_ensure_directory(void);

#endif // VAULT_CONTROLLER_H
