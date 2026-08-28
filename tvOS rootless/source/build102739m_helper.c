#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
extern int proc_pidpath(int pid, void *buffer, unsigned int buffersize);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

enum {
    DT_CS_OPS_CDHASH = 5,
    DT_CS_CDHASH_LEN = 20,
    DT_MAX_ENV_NAMES = 32,
    DT_MAX_ENV_NAME_BYTES = 128,
    DT_ENV_NAMES_HEX_CAPACITY =
        (DT_MAX_ENV_NAMES * ((DT_MAX_ENV_NAME_BYTES * 2) + 1)) + 1,
};

static int has_prefix(const char *value, const char *prefix)
{
    return value && prefix && strncmp(value, prefix, strlen(prefix)) == 0;
}

static int compare_env_names(const void *left, const void *right)
{
    return strcmp((const char *)left, (const char *)right);
}

static void append_hex(char *output, size_t capacity, size_t *offset,
    const unsigned char *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length && *offset + 2 < capacity; i++) {
        output[(*offset)++] = digits[bytes[i] >> 4];
        output[(*offset)++] = digits[bytes[i] & 0xf];
    }
    output[*offset] = '\0';
}

int main(int argc, char *argv[])
{
    if (argc != 5 || !argv[0] || strcmp(argv[1], "--probe") != 0
        || strcmp(argv[2], "BUILD102739M_REPAIRED_V6") != 0
        || strcmp(argv[3], "--nonce") != 0 || !argv[4][0])
        return 64;

    size_t env_count = 0;
    size_t env_name_count = 0;
    size_t dyld_count = 0;
    int dyld_insert_present = 0;
    int env_name_overflow = 0;
    int env_name_duplicates = 0;
    char env_names[DT_MAX_ENV_NAMES][DT_MAX_ENV_NAME_BYTES + 1] = {{0}};
    for (char **entry = environ; entry && *entry; entry++) {
        env_count++;
        if (has_prefix(*entry, "DYLD_"))
            dyld_count++;
        if (has_prefix(*entry, "DYLD_INSERT_LIBRARIES="))
            dyld_insert_present = 1;

        const char *separator = strchr(*entry, '=');
        size_t name_length = separator ? (size_t)(separator - *entry) : 0;
        if (!separator || name_length == 0 || name_length > DT_MAX_ENV_NAME_BYTES
            || env_name_count >= DT_MAX_ENV_NAMES) {
            env_name_overflow = 1;
            continue;
        }
        memcpy(env_names[env_name_count], *entry, name_length);
        env_names[env_name_count][name_length] = '\0';
        env_name_count++;
    }

    qsort(env_names, env_name_count, sizeof(env_names[0]), compare_env_names);
    for (size_t i = 1; i < env_name_count; i++) {
        if (strcmp(env_names[i - 1], env_names[i]) == 0)
            env_name_duplicates = 1;
    }

    char env_names_hex[DT_ENV_NAMES_HEX_CAPACITY] = {0};
    size_t env_names_hex_offset = 0;
    if (env_name_count == 0) {
        memcpy(env_names_hex, "NONE", sizeof("NONE"));
    } else {
        for (size_t i = 0; i < env_name_count; i++) {
            if (i != 0)
                env_names_hex[env_names_hex_offset++] = ',';
            append_hex(env_names_hex, sizeof(env_names_hex), &env_names_hex_offset,
                (const unsigned char *)env_names[i], strlen(env_names[i]));
        }
    }

    char actual_path[4096] = {0};
    if (proc_pidpath(getpid(), actual_path, sizeof(actual_path)) <= 0 || !actual_path[0])
        return 65;

    unsigned char self_cdhash[DT_CS_CDHASH_LEN] = {0};
    errno = 0;
    int self_cdhash_rc = csops(getpid(), DT_CS_OPS_CDHASH,
        self_cdhash, sizeof(self_cdhash));
    int self_cdhash_errno = self_cdhash_rc == 0 ? 0 : errno;
    char self_cdhash_hex[(DT_CS_CDHASH_LEN * 2) + 1] = {0};
    const char *self_cdhash_value = "UNAVAILABLE";
    if (self_cdhash_rc == 0) {
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < sizeof(self_cdhash); i++) {
            self_cdhash_hex[i * 2] = digits[self_cdhash[i] >> 4];
            self_cdhash_hex[(i * 2) + 1] = digits[self_cdhash[i] & 0xf];
        }
        self_cdhash_value = self_cdhash_hex;
    }

    int written = dprintf(STDOUT_FILENO,
        "BUILD102739M_HELPER_RECORD protocol=BUILD102739M_REPAIRED_V6 "
        "marker=BUILD102739M_REPAIRED_V6 nonce=%s pid=%d uid=%u euid=%u "
        "argc=%d argv_match=YES effective_env_count=%zu env_name_count=%zu "
        "env_names_hex=%s env_name_overflow=%s env_name_duplicates=%s "
        "dyld_env_count=%zu dyld_insert=%s "
        "argv0=%s actual_path=%s self_cdhash_rc=%d self_cdhash_errno=%d self_cdhash=%s\n",
        argv[4], getpid(), getuid(), geteuid(), argc, env_count, env_name_count,
        env_names_hex, env_name_overflow ? "YES" : "NO",
        env_name_duplicates ? "YES" : "NO", dyld_count,
        dyld_insert_present ? "PRESENT" : "ABSENT", argv[0], actual_path,
        self_cdhash_rc, self_cdhash_errno, self_cdhash_value);
    if (written <= 0)
        return 66;
    return self_cdhash_rc == 0 ? 0 : 67;
}
