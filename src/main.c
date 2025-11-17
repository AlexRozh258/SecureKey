#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "arg_parse.h"
#include "crypto_engine.h"
#include "vault_controller.h"
#include "totp_engine.h"
#include "utilities.h"

#define MAX_PASSWORD_LEN 256

static void display_password_strength(const char* password) {
    if (!password || strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty\n");
        return;
    }

    int length = strlen(password);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;

    for (int i = 0; i < length; i++) {
        if (password[i] >= 'a' && password[i] <= 'z') has_lower = 1;
        else if (password[i] >= 'A' && password[i] <= 'Z') has_upper = 1;
        else if (password[i] >= '0' && password[i] <= '9') has_digit = 1;
        else has_special = 1;
    }

    printf("Password strength analysis:\n");
    printf("  Length: %d characters %s\n", length, length >= 12 ? "[GOOD]" : length >= 8 ? "[OK]" : "[WEAK]");
    printf("  Lowercase letters: %s\n", has_lower ? "Yes" : "No");
    printf("  Uppercase letters: %s\n", has_upper ? "Yes" : "No");
    printf("  Digits: %s\n", has_digit ? "Yes" : "No");
    printf("  Special characters: %s\n", has_special ? "Yes" : "No");

    int score = check_password_strength(password);

    printf("\nOverall strength: ");
    if (score >= 6) {
        printf("STRONG\n");
    } else if (score >= 4) {
        printf("MODERATE\n");
    } else {
        printf("WEAK\n");
    }
}

int main(int argc, char* argv[]) {
    arguments_t args;

    if (parse_arguments(argc, argv, &args) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize crypto engine\n");
        return 1;
    }

    int ret = 0;

    switch (args.command) {
        case CMD_TOTP: {
            uint32_t code = generate_totp(args.totp_secret);
            printf("TOTP Code: %06u\n", code);
            crypto_cleanup();
            return 0;
        }

        case CMD_CHECK:
            display_password_strength(args.password);
            crypto_cleanup();
            return 0;

        case CMD_GENERATE: {
            char password[65];
            if (generate_random_password(password, sizeof(password), args.password_length) != 0) {
                fprintf(stderr, "Error: Failed to generate password\n");
                crypto_cleanup();
                return 1;
            }
            if (args.show_password) {
                printf("Generated password: %s\n", password);
            } else {
                printf("Generated password (hidden)\n");
                printf("Use --show to display the password\n");
            }
            crypto_cleanup();
            return 0;
        }

        default:
            break;
    }

    char master_password[MAX_PASSWORD_LEN];
    const char* vault_path = vault_get_default_path();

    if (args.vault_file[0] != '\0' && strcmp(args.vault_file, "securekey.vault") != 0) {
        vault_path = args.vault_file;
    }

    if (args.command == CMD_INIT) {
        if (vault_exists(vault_path)) {
            printf("Vault already exists at: %s\n", vault_path);
            printf("Do you want to overwrite it? (yes/no): ");
            char response[10];
            if (fgets(response, sizeof(response), stdin) == NULL ||
                (strcmp(response, "yes\n") != 0 && strcmp(response, "y\n") != 0)) {
                printf("Operation cancelled\n");
                crypto_cleanup();
                return 0;
            }
        }

        if (read_password_secure("Enter master password: ", master_password, MAX_PASSWORD_LEN) != 0) {
            fprintf(stderr, "Error: Failed to read password\n");
            crypto_cleanup();
            return 1;
        }

        char master_password_confirm[MAX_PASSWORD_LEN];
        if (read_password_secure("Confirm master password: ", master_password_confirm, MAX_PASSWORD_LEN) != 0) {
            fprintf(stderr, "Error: Failed to read password\n");
            secure_cleanup(master_password, MAX_PASSWORD_LEN);
            crypto_cleanup();
            return 1;
        }

        if (strcmp(master_password, master_password_confirm) != 0) {
            fprintf(stderr, "Error: Passwords do not match\n");
            secure_cleanup(master_password, MAX_PASSWORD_LEN);
            secure_cleanup(master_password_confirm, MAX_PASSWORD_LEN);
            crypto_cleanup();
            return 1;
        }

        secure_cleanup(master_password_confirm, MAX_PASSWORD_LEN);

        ret = vault_init(master_password, vault_path);
        secure_cleanup(master_password, MAX_PASSWORD_LEN);

        if (ret == 0) {
            printf("Vault initialized successfully at: %s\n", vault_path);
        } else {
            fprintf(stderr, "Error: Failed to initialize vault\n");
        }

        vault_cleanup();
        crypto_cleanup();
        return ret;
    }

    if (!vault_exists(vault_path)) {
        fprintf(stderr, "Error: Vault does not exist. Use 'init' command to create one.\n");
        crypto_cleanup();
        return 1;
    }

    if (read_password_secure("Enter master password: ", master_password, MAX_PASSWORD_LEN) != 0) {
        fprintf(stderr, "Error: Failed to read password\n");
        crypto_cleanup();
        return 1;
    }

    ret = vault_init(master_password, vault_path);
    secure_cleanup(master_password, MAX_PASSWORD_LEN);

    if (ret != 0) {
        fprintf(stderr, "Error: Failed to open vault (wrong password?)\n");
        vault_cleanup();
        crypto_cleanup();
        return 1;
    }

    switch (args.command) {
        case CMD_STORE: {
            char password[MAX_PASSWORD_LEN];
            if (read_password_secure("Enter password to store: ", password, MAX_PASSWORD_LEN) != 0) {
                fprintf(stderr, "Error: Failed to read password\n");
                ret = 1;
                break;
            }

            ret = vault_store(args.service, args.username, password,
                            args.totp_secret[0] ? args.totp_secret : NULL, 1);

            secure_cleanup(password, MAX_PASSWORD_LEN);

            if (ret == 0) {
                printf("Successfully stored entry for '%s' (%s)\n", args.service, args.username);
            } else {
                fprintf(stderr, "Error: Failed to store entry\n");
            }
            break;
        }

        case CMD_RETRIEVE: {
            VaultEntry entry;
            ret = vault_get(args.service, args.username, &entry);

            if (ret == 0) {
                printf("Service: %s\n", entry.service);
                printf("Username: %s\n", entry.username);

                if (args.show_password) {
                    printf("Password: %s\n", entry.password);
                } else {
                    printf("Password: [hidden] (use --show to display)\n");
                }

                if (entry.totp_secret[0] != '\0') {
                    uint32_t totp_code = generate_totp(entry.totp_secret);
                    printf("TOTP Secret: %s\n", entry.totp_secret);
                    printf("Current TOTP Code: %06u\n", totp_code);
                }

                secure_cleanup(&entry, sizeof(entry));
            } else {
                fprintf(stderr, "Error: Entry not found\n");
            }
            break;
        }

        case CMD_LIST:
            ret = vault_list();
            if (ret != 0) {
                fprintf(stderr, "Error: Failed to list entries\n");
            }
            break;

        case CMD_REMOVE:
            ret = vault_remove(args.service, args.username);
            if (ret == 0) {
                printf("Successfully removed entry for '%s' (%s)\n", args.service, args.username);
            } else {
                fprintf(stderr, "Error: Failed to remove entry (not found?)\n");
            }
            break;

        default:
            fprintf(stderr, "Error: Unknown command\n");
            ret = 1;
            break;
    }

    vault_cleanup();
    crypto_cleanup();

    return ret;
}
