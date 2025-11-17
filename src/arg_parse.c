#include "arg_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int parse_arguments(int argc, char *argv[], arguments_t *args) {
    if (argc < 2 || !argv || !args) {
        return -1;
    }
    
    args->command = CMD_NONE;
    args->service[0] = '\0';
    args->username[0] = '\0';
    strcpy(args->vault_file, "securekey.vault");
    args->totp_secret[0] = '\0';
    args->password[0] = '\0';
    args->password_length = 16;
    args->show_password = 0;
    args->verbose = 0;
    
    if (strcmp(argv[1], "store") == 0 || strcmp(argv[1], "add") == 0) {
        args->command = CMD_STORE;
    } else if (strcmp(argv[1], "get") == 0 || strcmp(argv[1], "retrieve") == 0) {
        args->command = CMD_RETRIEVE;
    } else if (strcmp(argv[1], "list") == 0 || strcmp(argv[1], "ls") == 0) {
        args->command = CMD_LIST;
    } else if (strcmp(argv[1], "remove") == 0 || strcmp(argv[1], "rm") == 0 || strcmp(argv[1], "delete") == 0) {
        args->command = CMD_REMOVE;
    } else if (strcmp(argv[1], "totp") == 0 || strcmp(argv[1], "2fa") == 0) {
        args->command = CMD_TOTP;
    } else if (strcmp(argv[1], "check") == 0 || strcmp(argv[1], "validate") == 0) {
        args->command = CMD_CHECK;
    } else if (strcmp(argv[1], "generate") == 0 || strcmp(argv[1], "gen") == 0) {
        args->command = CMD_GENERATE;
    } else if (strcmp(argv[1], "init") == 0) {
        args->command = CMD_INIT;
    } else if (strcmp(argv[1], "change-password") == 0 || strcmp(argv[1], "passwd") == 0) {
        args->command = CMD_CHANGE_PASSWORD;
    } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        exit(0);
    } else if (strcmp(argv[1], "--version") == 0) {
        print_version();
        exit(0);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
        return -1;
    }
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--service") == 0 || strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                strncpy(args->service, argv[++i], sizeof(args->service) - 1);
                args->service[sizeof(args->service) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: --service requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--username") == 0 || strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) {
                strncpy(args->username, argv[++i], sizeof(args->username) - 1);
                args->username[sizeof(args->username) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: --username requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--vault") == 0 || strcmp(argv[i], "-v") == 0) {
            if (i + 1 < argc) {
                strncpy(args->vault_file, argv[++i], sizeof(args->vault_file) - 1);
                args->vault_file[sizeof(args->vault_file) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: --vault requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--secret") == 0) {
            if (i + 1 < argc) {
                strncpy(args->totp_secret, argv[++i], sizeof(args->totp_secret) - 1);
                args->totp_secret[sizeof(args->totp_secret) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: --secret requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--password") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                strncpy(args->password, argv[++i], sizeof(args->password) - 1);
                args->password[sizeof(args->password) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: --password requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--length") == 0 || strcmp(argv[i], "-l") == 0) {
            if (i + 1 < argc) {
                args->password_length = atoi(argv[++i]);
                if (args->password_length < 8 || args->password_length > 64) {
                    fprintf(stderr, "Error: Password length must be between 8 and 64\n");
                    return -1;
                }
            } else {
                fprintf(stderr, "Error: --length requires a value\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--show") == 0) {
            args->show_password = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            args->verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            return -1;
        }
    }
    
    switch (args->command) {
        case CMD_STORE:
        case CMD_RETRIEVE:
        case CMD_REMOVE:
            if (args->service[0] == '\0') {
                fprintf(stderr, "Error: Command '%s' requires --service\n", argv[1]);
                return -1;
            }
            if (args->username[0] == '\0') {
                fprintf(stderr, "Error: Command '%s' requires --username\n", argv[1]);
                return -1;
            }
            break;
            
        case CMD_TOTP:
            if (args->totp_secret[0] == '\0') {
                fprintf(stderr, "Error: Command 'totp' requires --secret\n");
                return -1;
            }
            break;
            
        case CMD_CHECK:
            if (args->password[0] == '\0') {
                fprintf(stderr, "Error: Command 'check' requires --password\n");
                return -1;
            }
            break;
            
        case CMD_LIST:
        case CMD_GENERATE:
        case CMD_INIT:
            break;
            
        default:
            break;
    }
    
    return 0;
}

void print_usage(const char *program_name) {
    printf("SecureKey - Password Manager\n\n");
    printf("Usage: %s <command> [options]\n\n", program_name);
    
    printf("Commands:\n");
    printf("  store, add         Store a new password\n");
    printf("  get, retrieve      Retrieve a password\n");
    printf("  list, ls           List all stored services\n");
    printf("  remove, rm         Remove a stored password\n");
    printf("  totp, 2fa          Generate TOTP code\n");
    printf("  check, validate    Check password strength\n");
    printf("  generate, gen      Generate a strong password\n");
    printf("  init               Initialize new vault\n");
    printf("  change-password    Change vault master password\n\n");
    
    printf("Options:\n");
    printf("  -s, --service <name>    Service name (e.g., github, gmail)\n");
    printf("  -u, --username <name>   Username/email for the service\n");
    printf("  -v, --vault <file>      Vault file (default: securekey.vault)\n");
    printf("      --secret <key>      Base32 secret for TOTP\n");
    printf("  -p, --password <pass>   Password for strength checking\n");
    printf("  -l, --length <num>      Password length for generation (8-64)\n");
    printf("      --show              Show password in plain text\n");
    printf("      --verbose           Show detailed information\n");
    printf("  -h, --help              Show this help message\n");
    printf("      --version           Show version information\n\n");
    
    printf("Examples:\n");
    printf("  %s store -s github -u user@example.com\n", program_name);
    printf("  %s get -s github -u user@example.com\n", program_name);
    printf("  %s list --verbose\n", program_name);
    printf("  %s totp --secret JBSWY3DPEHPK3PXP\n", program_name);
    printf("  %s check -p 'MyPassword123!'\n", program_name);
    printf("  %s generate -l 20 --show\n", program_name);
    printf("  %s init -v my_vault.dat\n", program_name);
    printf("  %s change-password\n", program_name);
}

void print_version(void) {
    printf("SecureKey v1.0.0\n");
    printf("A secure command-line password manager with TOTP support\n");
}

const char* command_to_string(command_t cmd) {
    switch (cmd) {
        case CMD_STORE: return "store";
        case CMD_RETRIEVE: return "get";
        case CMD_LIST: return "list";
        case CMD_REMOVE: return "remove";
        case CMD_TOTP: return "totp";
        case CMD_CHECK: return "check";
        case CMD_GENERATE: return "generate";
        case CMD_INIT: return "init";
        case CMD_CHANGE_PASSWORD: return "change-password";
        default: return "unknown";
    }
}
