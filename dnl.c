#define _GNU_SOURCE
#include "dnl.h"
#include "dns.h"
#include "log.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

/* token stringize */
#define _literal(x) #x
#define literal(x) _literal(x)

#define DEFAULT_LCAP 4 /* 2^4 = 16 */
#define LOAD_FACTOR 0.75
#define MAX_COLLISION 4 /* max length of list in map1 */

// "www.google.com.hk"
#define LABEL_MAXCNT 4

typedef uint8_t u8_t;
typedef uint32_t u32_t;

typedef uint hashv_t; /* uthash.h */
typedef u8_t namelen_t;

#define BUCKET_FREE 0 /* free (unused) */
#define BUCKET_HEAD 1 /* list head */
#define BUCKET_BODY 2 /* list body (non-head) */
#define BUCKET_NEXT 3 /* find next-level map */

typedef struct bucket {
    u32_t state:2; // BUCKET_*
    u32_t tag:1; // NAME_TAG_* (gfw or chn)
    u32_t name:29; // addr in s_base
    u32_t next; // #list# bucket addr (-1: end)
} bucket_s;

typedef struct map {
    u32_t notnull; // map not-null
    u32_t buckets; // addr in s_base
    u32_t lcap; // log2 of cap
    u32_t freeidx; // find free-bucket from here
    u32_t nitems; // nitems stored in buckets
} map_s;

u32_t g_dnl_nitems = 0; /* total (gfw + chn) */

static map_s s_map1; /* L1 map (<= MAX_COLLISION) */
static map_s s_map2; /* L2 map (> MAX_COLLISION) */

/* ======================== alloc ======================== */

static void *s_base = NULL; /* page-aligned */
static u32_t s_cap = 0; /* multiple of page-size */
static u32_t s_end = 0; /* actual range of used */

static u32_t align_to(u32_t sz, u32_t align) {
    u32_t n = sz % align;
    if (n) sz += align - n;
    return sz;
}

/* contents are initialized to zero */
static u32_t alloc(u32_t sz, u32_t align) {
    assert(sz % align == 0);

    s_end = align_to(s_end, align);
    s_end += sz;

    if (s_end > s_cap) {
        u32_t oldcap = s_cap;
        s_cap = align_to(s_end, sysconf(_SC_PAGESIZE));
        if (!s_base)
            s_base = mmap(NULL, s_cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        else
            s_base = mremap(s_base, oldcap, s_cap, MREMAP_MAYMOVE);
        if (s_base == MAP_FAILED) {
            fprintf(stderr, "mmap/mremap failed. oldcap:%lu newcap:%lu errno:%d %s\n", (ulong)oldcap, (ulong)s_cap, errno, strerror(errno));
            abort();
        }
    }

    return s_end - sz;
}

#define addr(ptr) ((u32_t)((void *)(ptr) - s_base))
#define ptr(addr) (s_base + (addr)) // void *
#define ptr_bucket(addr) ((bucket_s *)ptr(addr))

#define alloc_name(sz) alloc(sz, 1) // todo align ?
#define alloc_bucket(n) alloc((n) * sizeof(bucket_s), __alignof__(bucket_s))

/* ======================== name ======================== */

/* struct name { hashv_t hashv; namelen_t namelen; char name[]; }; */

#define calc_hashv(name, namelen) ({ \
    hashv_t hashv_ = 0; \
    HASH_FCN(name, namelen, hashv_); /* uthash.h */ \
    hashv_; \
})

#define get_hashv(nameaddr) ({ \
    hashv_t hashv_; \
    memcpy(&hashv_, ptr(nameaddr), sizeof(hashv_)); \
    hashv_; \
})

#define set_hashv(nameaddr, hashv) \
    memcpy(ptr(nameaddr), &(hashv), sizeof(hashv))

#define get_namelen(nameaddr) ({ \
    namelen_t namelen_; \
    memcpy(&namelen_, ptr(nameaddr) + sizeof(hashv_t), sizeof(namelen_)); \
    namelen_; \
})

#define set_namelen(nameaddr, namelen) \
    memcpy(ptr(nameaddr) + sizeof(hashv_t), &(namelen), sizeof(namelen))

#define get_name(nameaddr) \
    (ptr(nameaddr) + sizeof(hashv_t) + sizeof(namelen_t))

#define set_name(nameaddr, name, namelen) \
    memcpy(get_name(nameaddr), name, namelen)

#define calc_namesz(namelen) \
    (sizeof(hashv_t) + sizeof(namelen_t) + (namelen))

#define get_namesz(nameaddr) \
    calc_namesz(get_namelen(nameaddr))

#define add_name(name) ({ \
    namelen_t namelen_ = strlen(name); \
    hashv_t hashv_ = calc_hashv(name, namelen_); \
    u32_t nameaddr_ = alloc_name(calc_namesz(namelen_)); \
    set_hashv(nameaddr_, hashv_); \
    set_namelen(nameaddr_, namelen_); \
    set_name(nameaddr_, name, namelen_); \
    nameaddr_; \
})

#define name_eq_r(addr, hashv, namelen, name) ( \
    get_hashv(addr) == (hashv) && \
    get_namelen(addr) == (namelen) && \
    memcmp(get_name(addr), name, namelen) == 0 \
)

#define name_eq(addr1, addr2) \
    ((addr1) == (addr2) || \
    name_eq_r(addr1, get_hashv(addr2), get_namelen(addr2), get_name(addr2)))

/* ======================== bucket ======================== */

#define calc_lcap(nitems) ({ \
    /* cap * factor => max_n_items */ \
    u32_t r_ = ceil((double)(nitems) / LOAD_FACTOR); \
    u32_t cap_ = 1; /* 2^n */ \
    u32_t lcap_ = 0; /* log2(cap), n */ \
    while (cap_ < r_) { cap_ <<= 1; lcap_++; } \
    lcap_; \
})

#define bucket_is_free(bucket) ((bucket)->state == BUCKET_FREE)
#define bucket_is_head(bucket) ((bucket)->state == BUCKET_HEAD)
#define bucket_is_body(bucket) ((bucket)->state == BUCKET_BODY)
#define bucket_in_next(bucket) ((bucket)->state == BUCKET_NEXT)

#define bucket_set_free(bucket) ((bucket)->state = BUCKET_FREE)
#define bucket_set_head(bucket) ((bucket)->state = BUCKET_HEAD)
#define bucket_set_body(bucket) ((bucket)->state = BUCKET_BODY)
#define bucket_set_next(bucket) ((bucket)->state = BUCKET_NEXT)

/* map1/map2 is a getter, can be passed as arg to macro func */
#define map1() (&s_map1)
#define map2() (&s_map2)

#define map_is_null(map) (!map()->notnull)
#define map_set_notnull(map, init_lcap) ({ \
    map()->notnull = 1; \
    map()->lcap = (init_lcap); \
    map()->buckets = alloc_bucket(map_cap(map)); \
})

#define dnl_is_null() map_is_null(map1)
#define dnl_set_notnull(init_lcap) map_set_notnull(map1, init_lcap)

#define map_nitems(map) (map()->nitems)
#define dnl_nitems() (map_nitems(map1) + map_nitems(map2))

#define map_cap(map) (1U << map()->lcap)
#define dnl_cap() (map_cap(map1) + map_cap(map2))
#define map_maxload(map) ((u32_t)((double)map_cap(map) * LOAD_FACTOR))

#define map_hashv(map, hashv) _##map##_hashv(hashv)
#define _map1_hashv(hashv) (hashv)
#define _map2_hashv(hashv) (_map1_hashv(hashv) >> map1()->lcap)

#define map_idx(map, hashv) (map_hashv(map, hashv) & (map_cap(map) - 1))

#define get_bucket_by_idx(map, idx) (ptr_bucket(map()->buckets) + (idx))
#define get_bucket_by_hashv(map, hashv) get_bucket_by_idx(map, map_idx(map, hashv))
#define get_bucket_by_nameaddr(map, nameaddr) get_bucket_by_hashv(map, get_hashv(nameaddr))

#define next_bucket(bucket) ((bucket)->next == (u32_t)-1 ? NULL : ptr_bucket((bucket)->next))
#define idx_of_bucket(map, bucket) ((bucket_s *)(bucket) - ptr_bucket(map()->buckets))

// find free bucket to use
#define take_free_bucket(map) ({ \
    bucket_s *fb_ = NULL; \
    for (u32_t idx_ = map()->freeidx, n_ = map_cap(map); idx_ < n_; ++idx_) { \
        bucket_s *b_ = get_bucket_by_idx(map, idx_); \
        if (bucket_is_free(b_)) { \
            map()->freeidx = idx_ + 1; /* start here next time */ \
            fb_ = b_; \
            break; \
        } \
    } \
    assert(fb_); \
    fb_; \
})

// free bucket
#define free_bucket(map, bucket) ({ \
    u32_t idx_ = idx_of_bucket(map, bucket); \
    assert(get_bucket_by_idx(map, idx_) == (bucket)); \
    if (idx_ < map()->freeidx) map()->freeidx = idx_; \
    bucket_set_free(bucket); \
})

#define foreach_list(head, cur) \
    for (bucket_s *cur = (head); cur; cur = next_bucket(cur))

#define return_if_exists(head, nameaddr) ({ \
    int n_nodes_ = 0; \
    foreach_list(head, cur) { \
        if (name_eq(cur->name, nameaddr)) return; \
        ++n_nodes_; \
    } \
    n_nodes_; \
})

#define store_as_head(map, head, nametag, nameaddr) ({ \
    bucket_set_head(head); \
    (head)->tag = (nametag); \
    (head)->name = (nameaddr); \
    (head)->next = -1; \
})

#define store_as_body(map, head, nametag, nameaddr) ({ \
    /* find free bucket */ \
    bucket_s *body_ = take_free_bucket(map); \
    bucket_set_body(body_); \
    body_->tag = (nametag); \
    body_->name = (nameaddr); \
    body_->next = (head)->next; \
    (head)->next = addr(body_); \
})

/* body to new pos, store head in this pos */
#define change_to_head(map, oldbody, headnametag, headnameaddr) ({ \
    /* copy from old to new */ \
    bucket_s *newbody_ = take_free_bucket(map); \
    bucket_set_body(newbody_); \
    newbody_->tag = (oldbody)->tag; \
    newbody_->name = (oldbody)->name; \
    newbody_->next = (oldbody)->next; \
    /* repair the list it is in */ \
    bucket_s *head_ = get_bucket_by_nameaddr(map, newbody_->name); \
    assert(bucket_is_head(head_)); \
    u32_t oldbodyaddr_ = addr(oldbody), found_ = 0; \
    foreach_list(head_, cur) { \
        if (cur->next == oldbodyaddr_) { \
            cur->next = addr(newbody_); \
            found_ = 1; \
            break; \
        } \
    } \
    (void)found_; /* avoid unused warning */ \
    assert(found_); \
    /* change it to head node */ \
    store_as_head(map, oldbody, headnametag, headnameaddr); \
})

static void resize_map2(void) {
    // grow *2 (may change the pool addr)
    u32_t addr = alloc_bucket(map_cap(map2));
    assert(ptr_bucket(addr) == ptr_bucket(map2()->buckets) + map_cap(map2));
    (void)addr; /* avoid unused warning */

    map2()->lcap++;

    // foreach part 1
    for (u32_t idx = 0, n = map_cap(map2) >> 1; idx < n; ++idx) {
        bucket_s *const head = get_bucket_by_idx(map2, idx);

        // ignore non-head node
        if (!bucket_is_head(head)) continue;

        // foreach list
        for (bucket_s *cur = head, *prev = NULL; cur;) {
            u32_t newidx = map_idx(map2, get_hashv(cur->name));

            if (newidx == idx) {
                /* still the same list pos */
                prev = cur;
                cur = next_bucket(cur);
            } else {
                /* must be in the part 2 */
                assert(newidx >= n);
                assert(newidx < map_cap(map2));

                u8_t nametag = cur->tag;
                u32_t nameaddr = cur->name;
                u32_t nextaddr = cur->next;
                bucket_s *next = next_bucket(cur);

                // remove from old list
                if (!prev) {
                    /* cur node is head */
                    assert(cur == head);
                    assert(bucket_is_head(cur));
                    if (next) {
                        /* next_node => head */
                        cur->tag = next->tag; // copy next node to head
                        cur->name = next->name; // copy next node to head
                        cur->next = next->next; // copy next node to head
                        free_bucket(map2, next); // free next node
                    } else {
                        /* list_size == 1 (only the head) */
                        free_bucket(map2, cur); // free it
                        cur = NULL; // foreach end
                    }
                } else {
                    /* cur node is body */
                    assert(bucket_is_body(cur));
                    free_bucket(map2, cur); // free cur node
                    prev->next = nextaddr; // repair list link
                    cur = next; // foreach from here
                }

                // add to new list
                bucket_s *newhead = get_bucket_by_idx(map2, newidx);
                if (bucket_is_free(newhead))
                    store_as_head(map2, newhead, nametag, nameaddr);
                else if (bucket_is_head(newhead))
                    store_as_body(map2, newhead, nametag, nameaddr);
                else if (bucket_is_body(newhead))
                    change_to_head(map2, newhead, nametag, nameaddr);
                else
                    assert(0);
            }
        }
    }
}

#define try_resize_map2() ({ \
    int resized_ = 0; \
    if (map2()->nitems >= map_maxload(map2)) { \
        resize_map2(); \
        resized_ = 1; \
    } \
    resized_; \
})

static void add_to_map2(u8_t nametag, u32_t nameaddr) {
    if (map_is_null(map2))
        map_set_notnull(map2, DEFAULT_LCAP);
    bucket_s *head;
redo:
    head = get_bucket_by_nameaddr(map2, nameaddr);
    if (bucket_is_free(head)) {
        if (try_resize_map2()) goto redo;
        store_as_head(map2, head, nametag, nameaddr);
        map2()->nitems++;
    } else if (bucket_is_head(head)) {
        return_if_exists(head, nameaddr);
        if (try_resize_map2()) goto redo;
        store_as_body(map2, head, nametag, nameaddr);
        map2()->nitems++;
    } else if (bucket_is_body(head)) {
        if (try_resize_map2()) goto redo;
        change_to_head(map2, head, nametag, nameaddr);
        map2()->nitems++;
    } else {
        assert(0);
    }
}

static void add_to_dnl(u8_t nametag, u32_t nameaddr) {
    bucket_s *head = get_bucket_by_nameaddr(map1, nameaddr);
    if (bucket_is_free(head)) {
        store_as_head(map1, head, nametag, nameaddr);
        map1()->nitems++;
    } else if (bucket_is_head(head)) {
        int n_nodes = return_if_exists(head, nameaddr);
        if (n_nodes < MAX_COLLISION) {
            store_as_body(map1, head, nametag, nameaddr);
            map1()->nitems++;
        } else {
            /* `resize_map2()` may change the `s_base`. so must be foreach by rel-addr */
            bucket_set_next(head); /* next time, find in the next-level buckets (map2) */
            u32_t headaddr = addr(head);
            for (u32_t addr = headaddr; addr != (u32_t)-1; addr = ptr_bucket(addr)->next) {
                map1()->nitems--;
                add_to_map2(ptr_bucket(addr)->tag, ptr_bucket(addr)->name);
                if (addr != headaddr) free_bucket(map1, ptr_bucket(addr));
            }
            add_to_map2(nametag, nameaddr);
        }
    } else if (bucket_is_body(head)) {
        change_to_head(map1, head, nametag, nameaddr);
        map1()->nitems++;
    } else {
        assert(bucket_in_next(head));
        add_to_map2(nametag, nameaddr);
    }
}

#define exists_in_list(head, hashv, namelen, NAME, p_tag) ({ \
    bool exists_ = false; \
    foreach_list(head, cur) { \
        if (name_eq_r(cur->name, hashv, namelen, NAME)) { \
            *(p_tag) = cur->tag; \
            exists_ = true; \
            break; \
        } \
    } \
    exists_; \
})

static bool exists_in_dnl(const char *noalias name, namelen_t namelen, u8_t *noalias p_tag) {
    hashv_t hashv = calc_hashv(name, namelen);
    bucket_s *head = get_bucket_by_hashv(map1, hashv);
    if (bucket_is_head(head)) {
        return exists_in_list(head, hashv, namelen, name, p_tag);
    } else if (bucket_in_next(head)) {
        head = get_bucket_by_hashv(map2, hashv);
        if (bucket_is_head(head))
            return exists_in_list(head, hashv, namelen, name, p_tag);
    }
    return false;
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

static bool load_list(const char *noalias filenames, u32_t *noalias p_addr0, u32_t *noalias p_nitems) {
    u32_t addr0 = 0, nitems = 0;

    for (int has_next = 1; has_next;) {
        const char *d = strchr(filenames, ',');
        size_t len = d ? (size_t)(d - filenames) : strlen(filenames);

        char fname[len + 1];
        memcpy(fname, filenames, len);
        fname[len] = '\0';

        if (d)
            filenames += len + 1;
        else
            has_next = 0;

        FILE *fp;
        if (strcmp(fname, "-") == 0) {
            fp = stdin;
        } else {
            fp = fopen(fname, "rb");
            if (!fp) {
                LOGE("failed to open '%s': (%d) %s", fname, errno, strerror(errno));
                continue;
            }
        }

        char buf[DNS_NAME_MAXLEN + 1];
        while (fscanf(fp, "%" literal(DNS_NAME_MAXLEN) "s", buf) > 0) {
            const char *name = trim_name(buf);
            if (name) {
                u32_t nameaddr = add_name(name);
                if (nitems++ == 0) addr0 = nameaddr;
            }
        }

        if (fp == stdin)
            freopen("/dev/null", "rb", stdin);
        else
            fclose(fp);
    }

    if (nitems <= 0) return false;

    *p_addr0 = addr0;
    *p_nitems = nitems;

    return true;
}

static u32_t add_list(u8_t nametag, u32_t addr0, u32_t nitems) {
    u32_t old_nitems = dnl_nitems();
    for (u32_t i = 0, nameaddr = addr0; i < nitems; ++i) {
        add_to_dnl(nametag, nameaddr);
        nameaddr += get_namesz(nameaddr);
    }
    return dnl_nitems() - old_nitems;
}

/* initialize domain-name-list from file */
void dnl_init(void) {
    u32_t gfw_addr0 = 0, gfw_nitems = 0;
    bool has_gfw = g_gfwlist_fname && load_list(g_gfwlist_fname, &gfw_addr0, &gfw_nitems);
    if (has_gfw) {
        double cost = (double)(s_end - gfw_addr0) / 1024.0;
        LOGI("gfwlist-name %lu %.3fk", (ulong)gfw_nitems, cost);
    }

    u32_t chn_addr0 = 0, chn_nitems = 0;
    bool has_chn = g_chnlist_fname && load_list(g_chnlist_fname, &chn_addr0, &chn_nitems);
    if (has_chn) {
        double cost = (double)(s_end - chn_addr0) / 1024.0;
        LOGI("chnlist-name %lu %.3fk", (ulong)chn_nitems, cost);
    }

    if (!has_gfw && !has_chn) return;

    /* first load_list() and then add_list() is friendly to malloc/realloc */

    dnl_set_notnull(calc_lcap(gfw_nitems + chn_nitems));

    if (has_gfw && has_chn) {
        if (g_gfwlist_first) {
            LOGI("gfwlist have higher priority");
            gfw_nitems = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
            chn_nitems = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
        } else {
            LOGI("chnlist have higher priority");
            chn_nitems = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
            gfw_nitems = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
        }
    } else if (has_gfw) {
        gfw_nitems = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
    } else {
        assert(has_chn);
        chn_nitems = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
    }

    g_dnl_nitems = dnl_nitems();
    assert(g_dnl_nitems == gfw_nitems + chn_nitems);

    if (has_gfw) {
        double cost = (double)(sizeof(bucket_s) * gfw_nitems) / 1024.0;
        LOGI("gfwlist-bucket %lu %.3fk", (ulong)gfw_nitems, cost);
    }
    if (has_chn) {
        double cost = (double)(sizeof(bucket_s) * chn_nitems) / 1024.0;
        LOGI("chnlist-bucket %lu %.3fk", (ulong)chn_nitems, cost);
    }
    u32_t n = dnl_cap() - g_dnl_nitems;
    double cost = (double)(sizeof(bucket_s) * n) / 1024.0;
    LOGI("other-bucket %lu %.3fk", (ulong)n, cost);

    /* total cost (page-aligned) */
    LOGI("total memory cost: %.3fk", (double)s_cap / 1024.0);
}

/* check if the given domain name matches */
u8_t get_name_tag(const char *noalias name, int namelen) {
    assert(!dnl_is_null());

    const char *noalias sub_names[LABEL_MAXCNT];
    int sub_namelens[LABEL_MAXCNT];

    assert(namelen > 0);
    int n = split_name(name, namelen, sub_names, sub_namelens);
    assert(n > 0);

    u8_t name_tag;
    for (int i = 0; i < n; ++i) {
        if (exists_in_dnl(sub_names[i], sub_namelens[i], &name_tag))
            return name_tag;
    }

    return g_default_tag;
}
