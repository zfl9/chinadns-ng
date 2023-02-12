#define _GNU_SOURCE
#include "dnlutils.h"
#include "dnsutils.h"
#include "logutils.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#undef _GNU_SOURCE

/* a very simple memory pool (alloc only) */
static void* mempool_alloc(size_t length) {
    static void  *mempool_buffer = NULL;
    static size_t mempool_length = 0;
    if (mempool_length < length) {
        /* arg.length must be <= 4096 */
        mempool_length = 4096; /* block size */
        mempool_buffer = malloc(mempool_length);
    }
    mempool_buffer += length;
    mempool_length -= length;
    return mempool_buffer - length;
}

/* hash entry typedef */
typedef struct {
    myhash_hh hh; /* TODO replace uthash to reduce memory usage */
    char dname[];
} dnlentry_t;

/* hash table (head entry) */
static dnlentry_t *g_gfwlist_headentry = NULL;
static dnlentry_t *g_chnlist_headentry = NULL;

// "www.google.com.hk"
#define LABEL_MAXCNT 4

// "a.www.google.com.hk" => "www.google.com.hk"
static const char * dname_trim(const char *dname) {
    unsigned dnamelen = strlen(dname);
    if (dnamelen < 1 || dname[0] == '.' || dname[dnamelen - 1] == '.') return NULL;

    unsigned labellen = 0, count = 0;
    for (int i = dnamelen - 1; i >= 0; --i) {
        if (dname[i] != '.') {
            if (++labellen > DNS_DNAME_LABEL_MAXLEN) return NULL;
        } else {
            if (labellen < 1) return NULL;
            labellen = 0;
            if (++count >= LABEL_MAXCNT) return dname + i + 1;
        }
    }
    return dname;
}

// used by dnl_init()
// "www.google.com.hk" => ["hk", "com.hk", "google.com.hk"], arraylen=3
static unsigned dname_subsplit(const char *dname, unsigned dnamelen, const char *sub_dnames[LABEL_MAXCNT - 1], unsigned sub_dnamelens[LABEL_MAXCNT - 1]) {
    unsigned arraylen = 0;
    for (int i = dnamelen - 1, n = 0; i >= 0; --i, ++n) {
        if (dname[i] == '.') {
            sub_dnames[arraylen] = dname + i + 1;
            sub_dnamelens[arraylen] = n;
            if (++arraylen >= LABEL_MAXCNT - 1) break;
        }
    }
    return arraylen;
}

// used by dnl_ismatch()
// "a.www.google.com.hk" => ["hk", "com.hk", "google.com.hk", "www.google.com.hk"], arraylen=4
static unsigned dname_split(const char *dname, unsigned dnamelen, const char *sub_dnames[LABEL_MAXCNT], unsigned sub_dnamelens[LABEL_MAXCNT]) {
    if (dname[0] == '.') return 0; //root-domain

    unsigned arraylen = 0;
    for (int i = dnamelen - 1, n = 0; i >= 0; --i, ++n) {
        if (dname[i] == '.') {
            sub_dnames[arraylen] = dname + i + 1;
            sub_dnamelens[arraylen] = n;
            if (++arraylen >= LABEL_MAXCNT) return arraylen;
        }
    }

    sub_dnames[arraylen] = dname;
    sub_dnamelens[arraylen] = dnamelen;
    return ++arraylen;
}

/* initialize domain-name-list from file */
size_t dnl_init(const char *filename, bool is_gfwlist) {
    FILE *fp = NULL;
    if (strcmp(filename, "-") == 0) {
        fp = stdin;
    } else {
        fp = fopen(filename, "rb");
        if (!fp) {
            LOGERR("[dnl_init] failed to open '%s': (%d) %s", filename, errno, strerror(errno));
            exit(errno);
        }
    }

    dnlentry_t **headentry = is_gfwlist ? &g_gfwlist_headentry : &g_chnlist_headentry;
    char strbuf[DNS_DOMAIN_NAME_MAXLEN]; //254(include \0)
    while (fscanf(fp, "%253s", strbuf) > 0) {
        const char *dname = dname_trim(strbuf);
        if (!dname) continue;

        dnlentry_t *entry = NULL;
        unsigned dnamelen = strlen(dname);
        MYHASH_GET(*headentry, entry, dname, dnamelen);
        if (entry) continue;

        entry = mempool_alloc(sizeof(dnlentry_t) + dnamelen); //without \0
        memcpy(entry->dname, dname, dnamelen);
        MYHASH_ADD(*headentry, entry, entry->dname, dnamelen); //keyptr usually points to the inside of the structure
    }
    if (fp != stdin) fclose(fp);

    //remove duplicate dnames
    const char *sub_dnames[LABEL_MAXCNT - 1];
    unsigned sub_dnamelens[LABEL_MAXCNT - 1];
    dnlentry_t *curentry = NULL, *tmpentry = NULL;
    MYHASH_FOR(*headentry, curentry, tmpentry) {
        unsigned arraylen = dname_subsplit(curentry->dname, curentry->hh.keylen, sub_dnames, sub_dnamelens);
        for (unsigned i = 0; i < arraylen; ++i) {
            dnlentry_t *findentry = NULL;
            MYHASH_GET(*headentry, findentry, sub_dnames[i], sub_dnamelens[i]);
            if (findentry) {
                MYHASH_DEL(*headentry, curentry);
                break;
            }
        }
    }
    return MYHASH_CNT(*headentry);
}

/* check if the given domain name matches */
uint8_t dnl_ismatch(const char *dname, bool is_gfwlist_first) {
    const char *sub_dnames[LABEL_MAXCNT];
    unsigned sub_dnamelens[LABEL_MAXCNT];
    unsigned arraylen = dname_split(dname, strlen(dname), sub_dnames, sub_dnamelens);
    if (arraylen <= 0) return DNL_MRESULT_NOMATCH;

    dnlentry_t *headentry = is_gfwlist_first ? g_gfwlist_headentry : g_chnlist_headentry;
    if (headentry) {
        for (unsigned i = 0; i < arraylen; ++i) {
            dnlentry_t *findentry = NULL;
            MYHASH_GET(headentry, findentry, sub_dnames[i], sub_dnamelens[i]);
            if (findentry) return is_gfwlist_first ? DNL_MRESULT_GFWLIST : DNL_MRESULT_CHNLIST;
        }
    }
    headentry = is_gfwlist_first ? g_chnlist_headentry : g_gfwlist_headentry;
    if (headentry) {
        for (unsigned i = 0; i < arraylen; ++i) {
            dnlentry_t *findentry = NULL;
            MYHASH_GET(headentry, findentry, sub_dnames[i], sub_dnamelens[i]);
            if (findentry) return is_gfwlist_first ? DNL_MRESULT_CHNLIST : DNL_MRESULT_GFWLIST;
        }
    }
    return DNL_MRESULT_NOMATCH;
}
