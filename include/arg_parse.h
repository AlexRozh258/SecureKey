#ifndef ARG_PARSE_H
#define ARG_PARSE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CMD_NONE,
    CMD_STORE,
    CMD_RETRIEVE,
    CMD_LIST,
    CMD_REMOVE,
    CMD_TOTP,
    CMD_CHECK,
    CMD_GENERATE,
    CMD_INIT,
    CMD_CHANGE_PASSWORD
} command_t;

typedef struct {
    command_t command;
    char service[64];
    char username[64];
    char vault_file[128];
    char totp_secret[128];
    char password[64];
    int password_length;
    int show_password;
    int verbose;
} arguments_t;

int parse_arguments(int argc, char *argv[], arguments_t *args);
void print_usage(const char *program_name);
void print_version(void);

const char* command_to_string(command_t cmd);

#ifdef __cplusplus
}
#endif

#endif
