#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "../src/dns.h"
#include "../src/misc.h"

struct header {
    i64 update_time;
    u32 hashv;
    i32 ttl;
    i32 ttl_r;
    u16 msg_len;
    u8 qnamelen;
    // msg: [msg_len]u8, // {header, question, answer, authority, additional}
};

#define alignto(n) __attribute__((aligned(n)))
#define printf_exit(msg, args...) ({ fprintf(stderr, msg "\n", ##args); exit(1); })

static bool next(FILE *file,
    struct header *h,
    void *msg, /* optional */
    char *name /* ascii name */)
{
    if (fread(h, sizeof(*h), 1, file) != 1)
        return false;

    char qname[DNS_NAME_WIRE_MAXLEN];

    if (msg) {
        if (fread(msg, h->msg_len, 1, file) < 1)
            printf_exit("fread(msg) failed");
        memcpy(qname, msg + dns_header_len(), h->qnamelen);
    } else {
        if (fseek(file, dns_header_len(), SEEK_CUR) < 0)
            printf_exit("skip dns_header failed: %m");
        if (fread(qname, h->qnamelen, 1, file) != 1)
            printf_exit("fread(qname) failed");
        if (fseek(file, h->msg_len - dns_header_len() - h->qnamelen, SEEK_CUR) < 0)
            printf_exit("skip dns_msg failed: %m");
    }

    if (!dns_wire_to_ascii(qname, h->qnamelen, name))
        printf_exit("invalid qname format");

    return true;
}

static void list(FILE *file) {
    struct header *h;
    char buf[sizeof(*h)] alignto(__alignof__(*h));
    h = (void *)buf;

    void *msg = malloc(DNS_MSG_MAXSIZE);
    char name[DNS_NAME_MAXLEN + 1];

    i64 now = time(NULL);
    while (next(file, h, msg, name))
        printf("%-60s qtype:%-5u ttl:%-10d size:%u\n",
            name, dns_get_qtype(msg, h->qnamelen),
            h->ttl - (i32)(now - h->update_time), h->msg_len);

    free(msg);
}

static void delete(FILE *file, const char *suffixes[], int suffix_n, const char *filepath) {
    struct header *h;
    char buf[sizeof(*h)] alignto(__alignof__(*h));
    h = (void *)buf;

    void *msg = malloc(DNS_MSG_MAXSIZE);
    char name[DNS_NAME_MAXLEN + 1];

    char tmp_filename[] = ".dns_cache_mgr.tmp.XXXXXX";
    int tmp_fd = mkstemp(tmp_filename);
    if (tmp_fd < 0)
        printf_exit("mkstemp() failed: %m");

next:
    while (next(file, h, msg, name)) {
        size_t namelen = strlen(name);
        for (int i = 0; i < suffix_n; i++) {
            const char *suffix = suffixes[i];
            size_t suffixlen = strlen(suffix);
            if (namelen >= suffixlen
                && memcmp(name + namelen - suffixlen, suffix, suffixlen) == 0
                && (namelen == suffixlen || name[namelen - suffixlen - 1] == '.'))
            {
                printf("%s\n", name);
                goto next;
            }
        }
        /* write to tmp file */
        write(tmp_fd, h, sizeof(*h));
        write(tmp_fd, msg, h->msg_len);
    }

    free(msg);

    close(tmp_fd);
    if (rename(tmp_filename, filepath) < 0)
        printf_exit("rename(old:'%s', new:'%s') failed: %m", tmp_filename, filepath);
}

int main(int argc, char *argv[]) {
    const char *path = "dns-cache.db";
    const char *suffixes[10];
    int suffix_n = 0;

    for (int i = 1; i < argc; i++) {
        #define next_arg() ({ \
            if (++i >= argc) \
                printf_exit("missing opt-value for '%s'", argv[i - 1]); \
            argv[i]; \
        })

        const char *arg = argv[i];
        if (strcmp(arg, "-f") == 0) {
            /* db file path */
            path = next_arg();
        } else if (strcmp(arg, "-r") == 0) {
            /* remove cache */
            if (suffix_n < (int)array_n(suffixes))
                suffixes[suffix_n++] = next_arg();
            else
                printf_exit("too many `-r suffix` options");
        } else {
            printf_exit(
                "unknown option or argument: '%s'\n"
                "\n"
                "list cache:\n"
                "- usage: %s\n"
                "\n"
                "remove cache:\n"
                "- usage: %s <-r suffix> ..."
                , arg, argv[0], argv[0]);
        }

        #undef next_arg
    }

    FILE *file = fopen(path, "rb+");
    if (!file)
        printf_exit("fopen('%s'): %m", path);

    if (suffix_n)
        delete(file, suffixes, suffix_n, path);
    else
        list(file);

    fclose(file);

    return 0;
}
