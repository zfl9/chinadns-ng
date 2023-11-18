#define _GNU_SOURCE
#include "dnl.h"
#include "dns.h"
#include "log.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/limits.h>

/* for L2 map */
#define DEFAULT_LCAP 4 /* 2^4 = 16 */

/* nitems / cap (for L2 map) */
#define LOAD_FACTOR_X 3 /* x/y */
#define LOAD_FACTOR_Y 4 /* x/y */

/* for L1 map */
#define MAX_COLLISION 4

/* "www.google.com.hk" */
#define LABEL_MAXCNT 4

/* u32 (bit-field) */
#define NAMEADDR_BIT 30

#define NAMEADDR_END ((u32)-1 & ((U32C(1) << NAMEADDR_BIT) - 1))

struct name {
    u32 next:NAMEADDR_BIT; /* addr in s_base */
    u32 tag:(32-NAMEADDR_BIT);
    uint hashv;
    u8 namelen;
    char name[];
} __attribute__((packed));

#define BUCKET_FREE 0 /* free */
#define BUCKET_HEAD 1 /* list head */
#define BUCKET_NEXT 2 /* find next-level map (L2) */

struct bucket {
    u32 state:(32-NAMEADDR_BIT); // BUCKET_*
    u32 head:NAMEADDR_BIT; // list-head (name-addr)
};

struct map {
    u32 notnull; // map not-null
    u32 buckets; // addr in s_base
    u32 lcap; // log2 of cap
    u32 nlists; // number of stored lists
    u32 nitems; // number of stored items
    u32 shift; // discard hashv low n bits
};

u32 g_dnl_nitems = 0; /* total (gfw + chn) */

static struct map s_map1; /* L1 map (<= MAX_COLLISION) */
static struct map s_map2; /* L2 map (> MAX_COLLISION) */

/* ======================== alloc ======================== */

static void *s_base = NULL; /* page-aligned */
static u32 s_cap = 0; /* multiple of page-size */
static u32 s_end = 0; /* actual range of used */

static u32 align_to(u32 sz, u32 align) {
    u32 n = sz % align;
    if (n) sz += align - n;
    return sz;
}

/* contents are initialized to zero */
static u32 alloc(u32 sz, u32 align) {
    s_end = align_to(s_end, align);
    s_end += sz;

    if (s_end > s_cap) {
        u32 oldcap = s_cap;
        s_cap = align_to(s_end, sysconf(_SC_PAGESIZE));
        if (!s_base)
            s_base = mmap(NULL, s_cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        else
            s_base = mremap(s_base, oldcap, s_cap, MREMAP_MAYMOVE);
        unlikely_if (s_base == MAP_FAILED)
            log_fatal("mmap/mremap failed. oldcap:%lu newcap:%lu errno:%d %s", (ulong)oldcap, (ulong)s_cap, errno, strerror(errno));
    }

    return s_end - sz;
}

#define addr(ptr) ((u32)((void *)(ptr) - s_base))

/* alloc may change `s_base`, so the pointer must be retrieved after alloc to prevent memory reference errors */
#define ptr(addr) (s_base + (addr))
#define ptr_name(addr) ((struct name *)ptr(addr))
#define ptr_bucket(addr) ((struct bucket *)ptr(addr))

#define alloc_name(namelen) \
    alloc(sizeof(struct name) + (namelen), __alignof__(struct name))

#define alloc_bucket(n) \
    alloc(sizeof(struct bucket) * (n), __alignof__(struct bucket))

/* ======================== name ======================== */

static inline uint calc_hashv(const char *noalias name, u8 namelen) {
    uint hashv = 0;
    HASH_FUNCTION(name, namelen, hashv); /* uthash.h */
    return hashv;
}

#define get_hashv(nameaddr) \
    (ptr_name(nameaddr)->hashv)

#define get_namesz(nameaddr) \
    (sizeof(struct name) + ptr_name(nameaddr)->namelen)

static inline u32 add_name(const char *noalias name, u8 tag) {
    u8 namelen = strlen(name);
    uint hashv = calc_hashv(name, namelen);
    u32 nameaddr = alloc_name(namelen);
    struct name *noalias p = ptr_name(nameaddr);
    p->next = NAMEADDR_END;
    p->tag = tag;
    p->hashv = hashv;
    p->namelen = namelen;
    memcpy(p->name, name, namelen);
    return nameaddr;
}

static inline bool name_eq_r(u32 addr, uint hashv, u8 namelen, const char *noalias name) {
    const struct name *noalias p = ptr_name(addr);
    return p->hashv == hashv && p->namelen == namelen && memcmp(p->name, name, namelen) == 0;
}

static inline bool name_eq(u32 addr1, u32 addr2) {
    const struct name *noalias p = ptr_name(addr2);
    return addr1 == addr2 || name_eq_r(addr1, p->hashv, p->namelen, p->name);
}

/* ======================== bucket ======================== */

/* for L1 map */
static inline u32 calc_lcap(u32 n) {
    u32 cap = 1; /* 2^n */
    u32 lcap = 0; /* log2(cap), n */
    while (cap < n) { cap <<= 1; lcap++; }
    return lcap;
}

#define map_is_null(map) (!(map)->notnull)
#define map_set_notnull(map, in_lcap, hashv_shift) ({ \
    (map)->notnull = 1; \
    (map)->lcap = (in_lcap); \
    (map)->buckets = alloc_bucket(map_cap(map)); \
    (map)->shift = (hashv_shift); \
})

#define dnl_is_null() map_is_null(&s_map1)
#define dnl_set_notnull(in_lcap, hashv_shift) map_set_notnull(&s_map1, in_lcap, hashv_shift)

#define map_cap(map) ((u32)1 << (map)->lcap)
#define map_maxload(map) ((u32)((ullong)map_cap(map) * LOAD_FACTOR_X / LOAD_FACTOR_Y)) /* for L2 map */

#define dnl_nitems() (s_map1.nitems + s_map2.nitems)

#define map_hashv(map, hashv) ((ullong)(hashv) >> (map)->shift)
#define map_idx(map, hashv) (map_hashv(map, hashv) & (map_cap(map) - 1))

#define get_bucket_by_idx(map, idx) (ptr_bucket((map)->buckets) + (idx))
#define get_bucket_by_hashv(map, hashv) get_bucket_by_idx(map, map_idx(map, hashv))
#define get_bucket_by_nameaddr(map, nameaddr) get_bucket_by_hashv(map, get_hashv(nameaddr))

#define next_nameaddr(addr) ((addr) == NAMEADDR_END ? NAMEADDR_END : ptr_name(addr)->next)

/* delete-safe && realloc-safe (by nameaddr) */
#define foreach_list(bucket, curaddr) \
    for (u32 curaddr = (bucket)->head, nextaddr_ = next_nameaddr(curaddr); \
        curaddr != NAMEADDR_END; curaddr = nextaddr_, nextaddr_ = next_nameaddr(curaddr))

#define return_if_exists(bucket, nameaddr) ({ \
    int n_ = 0; \
    foreach_list(bucket, curaddr) { \
        if (name_eq(curaddr, nameaddr)) return; \
        ++n_; \
    } \
    n_; \
})

#define store_as_head(bucket, nameaddr) ({ \
    assert((bucket)->state == BUCKET_FREE); \
    (bucket)->state = BUCKET_HEAD; \
    (bucket)->head = (nameaddr); \
    ptr_name(nameaddr)->next = NAMEADDR_END; \
})

#define store_as_body(bucket, nameaddr) ({ \
    assert((bucket)->state == BUCKET_HEAD); \
    ptr_name(nameaddr)->next = (bucket)->head; \
    (bucket)->head = (nameaddr); \
})

static bool resize_map2(void) {
    struct map *noalias map = &s_map2;

    /* check max-load */
    if (map->nitems < map_maxload(map)) return false;

    // grow *2 (may change the pool addr)
    u32 addr = alloc_bucket(map_cap(map));
    assert(ptr_bucket(addr) == ptr_bucket(map->buckets) + map_cap(map));
    (void)addr; /* avoid unused warning */

    map->lcap++;

    // foreach part 1
    for (u32 idx = 0, n = map_cap(map) >> 1; idx < n; ++idx) {
        struct bucket *noalias bucket = get_bucket_by_idx(map, idx);

        /* skip the non-head bucket */
        if (bucket->state != BUCKET_HEAD) continue;

        /* no realloc during foreach, so it is safe to use pointer */
        struct name *prev = NULL;

        foreach_list(bucket, curaddr) {
            struct name *cur = ptr_name(curaddr);

            u32 newidx = map_idx(map, cur->hashv);
            if (newidx == idx) {
                prev = cur;
                continue;
            }

            /* must be in part 2 */
            assert(newidx >= n);
            assert(newidx < map_cap(map));

            if (prev)
                prev->next = cur->next;
            else if (cur->next != NAMEADDR_END)
                bucket->head = cur->next;
            else {
                bucket->state = BUCKET_FREE;
                map->nlists--;
            }

            struct bucket *noalias newbucket = get_bucket_by_idx(map, newidx);
            switch (newbucket->state) {
                case BUCKET_FREE:
                    store_as_head(newbucket, curaddr);
                    map->nlists++;
                    break;
                default:
                    assert(newbucket->state == BUCKET_HEAD);
                    store_as_body(newbucket, curaddr);
                    break;
            }
        }
    }

    return true;
}

static void add_to_map2(u32 nameaddr) {
    struct map *noalias map = &s_map2;
    if (map_is_null(map))
        map_set_notnull(map, DEFAULT_LCAP, s_map1.lcap);
redo:;
    struct bucket *noalias bucket = get_bucket_by_nameaddr(map, nameaddr);
    switch (bucket->state) {
        case BUCKET_FREE:
            if (resize_map2()) goto redo;
            store_as_head(bucket, nameaddr);
            map->nitems++;
            map->nlists++;
            break;
        default:
            assert(bucket->state == BUCKET_HEAD);
            return_if_exists(bucket, nameaddr);
            if (resize_map2()) goto redo;
            store_as_body(bucket, nameaddr);
            map->nitems++;
            break;
    }
}

/* L1 map is pre-allocated */
static void add_to_dnl(u32 nameaddr) {
    struct map *noalias map = &s_map1;
    struct bucket *noalias bucket = get_bucket_by_nameaddr(map, nameaddr);
    switch (bucket->state) {
        case BUCKET_FREE:
            store_as_head(bucket, nameaddr);
            map->nitems++;
            map->nlists++;
            break;
        case BUCKET_HEAD: {
            int n = return_if_exists(bucket, nameaddr);
            if (n < MAX_COLLISION) {
                store_as_body(bucket, nameaddr);
                map->nitems++;
            } else {
                /* add_to_map2() may realloc, so `bucket` must be accessed before it */
                map->nlists--;
                bucket->state = BUCKET_NEXT; /* find in the next-level buckets (map2) */
                foreach_list(bucket, curaddr) {
                    map->nitems--;
                    add_to_map2(curaddr);
                }
                add_to_map2(nameaddr);
            }
            break;
        }
        default:
            assert(bucket->state == BUCKET_NEXT);
            add_to_map2(nameaddr);
            break;
    }
}

static bool exists_in_list(const struct bucket *noalias bucket,
    uint hashv, u8 namelen, const char *noalias name, u8 *noalias tag)
{
    foreach_list(bucket, curaddr) {
        if (name_eq_r(curaddr, hashv, namelen, name)) {
            *tag = ptr_name(curaddr)->tag;
            return true;
        }
    }
    return false;
}

static bool exists_in_dnl(const char *noalias name, u8 namelen, u8 *noalias tag) {
    uint hashv = calc_hashv(name, namelen);
    const struct bucket *noalias bucket = get_bucket_by_hashv(&s_map1, hashv);
    switch (bucket->state) {
        case BUCKET_HEAD:
            return exists_in_list(bucket, hashv, namelen, name, tag);
        case BUCKET_NEXT:
            bucket = get_bucket_by_hashv(&s_map2, hashv);
            return bucket->state == BUCKET_HEAD && exists_in_list(bucket, hashv, namelen, name, tag);
        default:
            return false;
    }
}

// "a.www.google.com.hk" => "www.google.com.hk"
static const char *trim_name(const char *name) {
    int namelen = strlen(name);
    if (namelen < 1 || name[0] == '.' || name[namelen - 1] == '.') return NULL;
    int labellen = 0, count = 0;
    for (int i = namelen - 1; i >= 0; --i) {
        if (name[i] != '.') {
            if (++labellen > DNS_NAME_LABEL_MAXLEN) return NULL;
        } else {
            if (labellen < 1) return NULL;
            labellen = 0;
            if (++count >= LABEL_MAXCNT) return name + i + 1;
        }
    }
    return name;
}

/* "a.www.google.com.hk" => ["hk", "com.hk", "google.com.hk", "www.google.com.hk"], arraylen=LABEL_MAXCNT */
static int split_name(const char *noalias name, int namelen, const char *noalias sub_names[noalias], int sub_namelens[noalias]) {
    int n = 0;
    const char *p, *end;
    p = end = name + namelen;
    while (n < LABEL_MAXCNT && (p = memrchr(name, '.', p - name))) {
        sub_names[n] = p + 1;
        sub_namelens[n] = end - (p + 1);
        ++n;
    }
    if (n < LABEL_MAXCNT) { /* p is NULL */
        sub_names[n] = name;
        sub_namelens[n] = namelen;
        ++n;
    }
    return n;
}

static bool load_list(u8 tag, const char *noalias filenames, u32 *noalias p_addr0, u32 *noalias p_n) {
    u32 addr0 = 0, n = 0;
    int has_next = 1;

    do {
        const char *start = filenames, *end;
        size_t len;
        if ((end = strchr(start, ','))) {
            len = end - start;
            filenames = end + 1;
        } else {
            len = strlen(start);
            has_next = 0;
        }

        unlikely_if (len + 1 > PATH_MAX) {
            log_error("path max length is %d: %.*s", PATH_MAX - 1, (int)len, start);
            continue;
        }

        char fname[PATH_MAX];
        memcpy(fname, start, len);
        fname[len] = '\0';

        FILE *fp;
        if (strcmp(fname, "-") == 0) {
            fp = stdin;
        } else {
            fp = fopen(fname, "rb");
            unlikely_if (!fp) {
                log_error("failed to open '%s': (%d) %s", fname, errno, strerror(errno));
                continue;
            }
        }

        char buf[DNS_NAME_MAXLEN + 1];
        while (fscanf(fp, "%" literal(DNS_NAME_MAXLEN) "s", buf) > 0) {
            const char *name = trim_name(buf);
            if (name) {
                u32 nameaddr = add_name(name, tag);
                if (n++ == 0) addr0 = nameaddr;
            }
        }

        if (fp == stdin)
            freopen("/dev/null", "rb", stdin);
        else
            fclose(fp);
    } while (has_next);

    if (n <= 0) return false;

    *p_addr0 = addr0;
    *p_n = n;

    return true;
}

static u32 add_list(u32 addr0, u32 n) {
    u32 old_nitems = dnl_nitems();
    for (u32 i = 0, nameaddr = addr0; i < n; ++i) {
        add_to_dnl(nameaddr);
        nameaddr += get_namesz(nameaddr);
    }
    return dnl_nitems() - old_nitems;
}

#ifdef DEBUG
static void do_debug(u32 gfw_addr0, u32 gfw_n, u32 chn_addr0, u32 chn_n) {
    const char *tagname_vec[] = {"gfwlist", "chnlist"};
    u8 tag_vec[] = {NAME_TAG_GFW, NAME_TAG_CHN};
    u32 addr0_vec[] = {gfw_addr0, chn_addr0};
    u32 n_vec[] = {gfw_n, chn_n};

    /* test hash lookup */
    for (int veci = 0; veci < (int)array_n(tagname_vec); ++veci) {
        const char *tagname = tagname_vec[veci];
        u8 tag = tag_vec[veci];
        u32 addr0 = addr0_vec[veci];
        u32 n = n_vec[veci];

        for (u32 i = 0, addr = addr0; i < n; ++i, addr += get_namesz(addr)) {
            const struct name *name = ptr_name(addr);
            char tmp[DNS_NAME_MAXLEN + 1] = {0};
            int namelen = name->namelen;
            memcpy(tmp, name->name, namelen);

            u8 tag1;
            if (!exists_in_dnl(name->name, namelen, &tag1))
                log_fatal("[%s] #raw test failed: %.*s", tagname, namelen, name->name);
            if (tag1 != tag) /* dup with chnlist ? */
                log_debug("[%s] duplicate: %.*s (tag:%s)", tagname, namelen, name->name, nametag_val2name(tag1));

            u8 tag2;
            if (!exists_in_dnl(tmp, namelen, &tag2))
                log_fatal("[%s] #copy test failed: %.*s", tagname, namelen, name->name);
            if (tag2 != tag1)
                log_fatal("[%s] tag1:%s != tag2:%s (%.*s)", tagname, nametag_val2name(tag1), nametag_val2name(tag2), namelen, name->name);

            *tmp = '.';
            if (exists_in_dnl(tmp, namelen, &tag2))
                log_fatal("[%s] #fake test failed: %.*s", tagname, namelen, name->name);
        }
    }

    /* check map2 hash collisions */
    if (!map_is_null(&s_map2)) {
        int maxlen = 0;
        for (u32 idx = 0, n = map_cap(&s_map2); idx < n; ++idx) {
            const struct bucket *bucket = get_bucket_by_idx(&s_map2, idx);
            if (bucket->state == BUCKET_HEAD) {
                int len = 0;
                foreach_list(bucket, curaddr) ++len;
                maxlen = max(len, maxlen);
                if (len >= MAX_COLLISION) {
                    log_debug("[map2_list] #list:%d >= MAX_COLLISION:%d", len, MAX_COLLISION);
                    int i = 0;
                    foreach_list(bucket, curaddr)
                        log_debug("[map2_list] >> [%d] %.*s", ++i, (int)ptr_name(curaddr)->namelen, ptr_name(curaddr)->name);
                }
            }
        }
        log_debug("[map2_list] max #list: %d", maxlen);
    }
}
#endif

void dnl_init(void) {
    u32 gfw_addr0 = 0, gfw_n = 0, gfw_cost, gfw_nitems = 0;
    bool has_gfw = g_gfwlist_fname && load_list(NAME_TAG_GFW, g_gfwlist_fname, &gfw_addr0, &gfw_n);
    gfw_cost = has_gfw ? s_end - gfw_addr0 : 0;

    u32 chn_addr0 = 0, chn_n = 0, chn_cost, chn_nitems = 0;
    bool has_chn = g_chnlist_fname && load_list(NAME_TAG_CHN, g_chnlist_fname, &chn_addr0, &chn_n);
    chn_cost = has_chn ? s_end - chn_addr0 : 0;

    if (!has_gfw && !has_chn) return;

    /* first load_list() and then add_list() is friendly to malloc/realloc */

    dnl_set_notnull(calc_lcap(gfw_n + chn_n), 0);

    if (has_gfw && has_chn) {
        if (g_gfwlist_first) {
            log_info("gfwlist have higher priority");
            gfw_nitems = add_list(gfw_addr0, gfw_n);
            chn_nitems = add_list(chn_addr0, chn_n);
        } else {
            log_info("chnlist have higher priority");
            chn_nitems = add_list(chn_addr0, chn_n);
            gfw_nitems = add_list(gfw_addr0, gfw_n);
        }
    } else if (has_gfw) {
        gfw_nitems = add_list(gfw_addr0, gfw_n);
    } else {
        assert(has_chn);
        chn_nitems = add_list(chn_addr0, chn_n);
    }

    g_dnl_nitems = dnl_nitems();
    assert(g_dnl_nitems == gfw_nitems + chn_nitems);

    if (has_chn)
        log_info("chnlist loaded:%lu added:%lu cost:%.3fk", (ulong)chn_n, (ulong)chn_nitems, chn_cost/1024.0);

    if (has_gfw)
        log_info("gfwlist loaded:%lu added:%lu cost:%.3fk", (ulong)gfw_n, (ulong)gfw_nitems, gfw_cost/1024.0);

    log_info("L1 items:%lu lists:%lu buckets:%lu cost:%.3fk",
        (ulong)s_map1.nitems, (ulong)s_map1.nlists, (ulong)map_cap(&s_map1), map_cap(&s_map1)*sizeof(struct bucket)/1024.0);

    if (!map_is_null(&s_map2)) 
        log_info("L2 items:%lu lists:%lu buckets:%lu cost:%.3fk",
            (ulong)s_map2.nitems, (ulong)s_map2.nlists, (ulong)map_cap(&s_map2), map_cap(&s_map2)*sizeof(struct bucket)/1024.0);

    log_info("total memory cost (page-aligned): %.3fk", s_cap/1024.0);

#ifdef DEBUG
    do_debug(gfw_addr0, gfw_n, chn_addr0, chn_n);
#endif
}

u8 get_name_tag(const char *noalias name, int namelen) {
    assert(!dnl_is_null());

    const char *noalias sub_names[LABEL_MAXCNT];
    int sub_namelens[LABEL_MAXCNT];

    assert(namelen > 0);
    assert((u8)namelen == namelen);
    int n = split_name(name, namelen, sub_names, sub_namelens);
    assert(n > 0);

    u8 name_tag;
    while (--n >= 0) {
        if (exists_in_dnl(sub_names[n], sub_namelens[n], &name_tag))
            return name_tag;
    }

    return g_default_tag;
}
