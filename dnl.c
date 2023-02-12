#define _GNU_SOURCE
#include "dnl.h"
#include "dns.h"
#include "log.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <assert.h>

/* token stringize */
#define _literal(x) #x
#define literal(x) _literal(x)

/* token concat */
#define _concat(a, b) a##b
#define concat(a, b) _concat(a, b)

#define DEFAULT_LCAP 4 /* 2^4 = 16 */
#define LOAD_FACTOR 0.75
#define MAX_COLLISION 4 /* max length of list in L1 */

// "www.google.com.hk"
#define LABEL_MAXCNT 4

typedef uint8_t u8_t;
typedef uint32_t u32_t;

typedef unsigned hashv_t; /* uthash.h */
typedef u8_t namelen_t;

#define BUCKET_FREE 0 /* free (unused) */
#define BUCKET_HEAD 1 /* list head */
#define BUCKET_BODY 2 /* list body (non-head) */
#define BUCKET_NEXT 3 /* find next-level map */

typedef struct bucket {
    u32_t state:2; // BUCKET_*
    u32_t name:30; // addr in pool
    u32_t next; // #list# bucket idx (-1: end)
} bucket_s;

typedef struct map {
    u32_t notnull; // map not-null
    u32_t buckets; // addr in pool
    u32_t lcap; // log2 of cap
    u32_t freeidx; // find free-bucket from here
    u32_t nitems; // n_items stored in buckets
} map_s;

typedef struct dnl {
    map_s L1; /* L1 map */
    map_s L2; /* L2 map */
} dnl_s;

static dnl_s g_chnlist; // = {0};
static dnl_s g_gfwlist; // = {0};

static char *g_name_pool     = NULL;
static u32_t g_name_poolcap  = 0;
static u32_t g_name_poolused = 0;

static bucket_s *g_bucket_pool     = NULL;
static u32_t     g_bucket_poolcap  = 0;
static u32_t     g_bucket_poolused = 0;

#define pool(tag)     g_##tag##_pool
#define poolcap(tag)  g_##tag##_poolcap
#define poolused(tag) g_##tag##_poolused

// return addr in pool
#define pool_alloc(tag, n) ({ \
    poolused(tag) += (n); \
    if (poolcap(tag) < poolused(tag)) { \
        poolcap(tag) = poolused(tag); \
        pool(tag) = realloc(pool(tag), poolcap(tag) * sizeof(*pool(tag))); \
        if (!pool(tag)) { \
            fprintf(stderr, "can't alloc memory. tag:%s n:%ld newcap:%ld\n", #tag, (long)(n), (long)poolcap(tag)); \
            abort(); \
        } \
    } \
    poolused(tag) - (n); \
})

#define alloc_name(sz) pool_alloc(name, sz)

#define _alloc_bucket(n) pool_alloc(bucket, n)

#define alloc_bucket(n) ({ \
    u32_t addr_ = _alloc_bucket(n); \
    memset(g_bucket_pool + addr_, 0, (n) * sizeof(bucket_s)); \
    addr_; \
})

#define get_hashv(nameaddr) ({ \
    hashv_t hashv_; \
    memcpy(&hashv_, g_name_pool + (nameaddr), sizeof(hashv_)); \
    hashv_; \
})

#define set_hashv(nameaddr, hashv) \
    memcpy(g_name_pool + (nameaddr), &(hashv), sizeof(hashv))

#define get_namelen(nameaddr) ({ \
    namelen_t namelen_; \
    memcpy(&namelen_, g_name_pool + (nameaddr) + sizeof(hashv_t), sizeof(namelen_)); \
    namelen_; \
})

#define set_namelen(nameaddr, namelen) \
    memcpy(g_name_pool + (nameaddr) + sizeof(hashv_t), &(namelen), sizeof(namelen))

#define ptr_name(nameaddr) \
    (g_name_pool + (nameaddr) + sizeof(hashv_t) + sizeof(namelen_t))

#define set_name(nameaddr, name, namelen) \
    memcpy(g_name_pool + (nameaddr) + sizeof(hashv_t) + sizeof(namelen_t), name, namelen)

#define calc_namesz(namelen) \
    (sizeof(hashv_t) + sizeof(namelen_t) + (namelen))

#define get_namesz(nameaddr) \
    calc_namesz(get_namelen(nameaddr))

#define calc_hashv(name, namelen) ({ \
    hashv_t hashv_ = 0; \
    HASH_FCN(name, namelen, hashv_); \
    hashv_; \
})

#define name_eq_r(addr, hashv, namelen, name) ( \
    get_hashv(addr) == (hashv) && \
    get_namelen(addr) == (namelen) && \
    memcmp(ptr_name(addr), name, namelen) == 0 \
)

#define name_eq(addr1, addr2) \
    ((addr1) == (addr2) || \
    name_eq_r(addr1, get_hashv(addr2), get_namelen(addr2), ptr_name(addr2)))

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

#define L1(dnl) (&(dnl)->L1)
#define L2(dnl) (&(dnl)->L2)

#define map_is_null(map) (!(map)->notnull)
#define map_set_notnull(map) ((map)->notnull = 1)

#define dnl_is_null(dnl) map_is_null(L1(dnl))
#define dnl_set_notnull(dnl) map_set_notnull(L1(dnl))

#define map_cap(map) (1 << (map)->lcap)
#define map_maxload(map) ((u32_t)((double)map_cap(map) * LOAD_FACTOR))

#define L1_cap(dnl) map_cap(L1(dnl))
#define L2_cap(dnl) map_cap(L2(dnl))

#define L1_hashv(dnl, hashv) (hashv)
#define L2_hashv(dnl, hashv) (L1_hashv(dnl, hashv) >> L1(dnl)->lcap)

#define L1_idx(dnl, hashv) (L1_hashv(dnl, hashv) & (L1_cap(dnl) - 1))
#define L2_idx(dnl, hashv) (L2_hashv(dnl, hashv) & (L2_cap(dnl) - 1))

#define get_bucket(map, idx) (g_bucket_pool + (map)->buckets + (idx))
#define idx_of_bucket(map, bucket) ((bucket) - g_bucket_pool - (map)->buckets)
#define next_bucket(map, bucket) ((bucket)->next == (u32_t)-1 ? NULL : get_bucket(map, (bucket)->next))

#define L1_bucket_by_hashv(dnl, hashv) get_bucket(L1(dnl), L1_idx(dnl, hashv))
#define L2_bucket_by_hashv(dnl, hashv) get_bucket(L2(dnl), L2_idx(dnl, hashv))
#define L1_bucket_by_nameaddr(dnl, nameaddr) L1_bucket_by_hashv(dnl, get_hashv(nameaddr))
#define L2_bucket_by_nameaddr(dnl, nameaddr) L2_bucket_by_hashv(dnl, get_hashv(nameaddr))

// find free idx to use (consume it)
#define find_free_idx(map) ({ \
    u32_t idx_ = (map)->freeidx, n_ = map_cap(map), found_ = 0; \
    for (; idx_ < n_; ++idx_) { \
        if (bucket_is_free(get_bucket(map, idx_))) { \
            (map)->freeidx = idx_ + 1; /* start here next time */ \
            found_ = 1; \
            break; \
        } \
    } \
    (void)found_; /* avoid unused warning */ \
    assert(found_); \
    idx_; \
})

// free bucket
#define free_bucket(map, bucket) ({ \
    u32_t idx_ = idx_of_bucket(map, bucket); \
    assert(get_bucket(map, idx_) == (bucket)); \
    if (idx_ < (map)->freeidx) (map)->freeidx = idx_; \
    bucket_set_free(bucket); \
})

#define foreach_list(map, head, cur) \
    for (bucket_s *cur = (head); cur; cur = next_bucket(map, cur))

#define return_if_exists(map, head, nameaddr) ({ \
    int n_nodes_ = 0; \
    foreach_list(map, head, cur) { \
        if (name_eq(cur->name, nameaddr)) return; \
        ++n_nodes_; \
    } \
    n_nodes_; \
})

#define store_as_head(head, nameaddr) ({ \
    bucket_set_head(head); \
    (head)->name = (nameaddr); \
    (head)->next = -1; \
})

#define store_as_body(map, head, nameaddr) ({ \
    /* find free bucket */ \
    u32_t bodyidx_ = find_free_idx(map); \
    bucket_s *body_ = get_bucket(map, bodyidx_); \
    bucket_set_body(body_); \
    body_->name = (nameaddr); \
    body_->next = (head)->next; \
    (head)->next = bodyidx_; \
})

/* body to new pos, store head in this pos */
#define change_to_head(dnl, Ln, oldbody, headnameaddr) ({ \
    /* calc oldbody idx */ \
    map_s *map_ = Ln(dnl); \
    u32_t oldbodyidx_ = idx_of_bucket(map_, oldbody); \
    assert(get_bucket(map_, oldbodyidx_) == (oldbody)); \
    /* copy from old to new */ \
    u32_t newbodyidx_ = find_free_idx(map_); \
    bucket_s *newbody_ = get_bucket(map_, newbodyidx_); \
    bucket_set_body(newbody_); \
    newbody_->name = (oldbody)->name; \
    newbody_->next = (oldbody)->next; \
    /* repair the list it is in */ \
    bucket_s *head_ = concat(Ln, _bucket_by_nameaddr(dnl, newbody_->name)); \
    assert(bucket_is_head(head_)); \
    foreach_list(map_, head_, cur) { \
        if (cur->next == oldbodyidx_) { \
            cur->next = newbodyidx_; \
            break; \
        } \
    } \
    /* change it to head node */ \
    store_as_head(oldbody, headnameaddr); \
})

static u32_t add_to_namepool(const char *name) {
    namelen_t namelen = strlen(name);
    hashv_t hashv = calc_hashv(name, namelen);
    u32_t nameaddr = alloc_name(calc_namesz(namelen));
    set_hashv(nameaddr, hashv);
    set_namelen(nameaddr, namelen);
    set_name(nameaddr, name, namelen);
    return nameaddr;
}

static void resize_L2(dnl_s *dnl) {
    map_s *map = L2(dnl);

    // grow *2 (may change the pool addr)
    u32_t addr = alloc_bucket(map_cap(map));
    assert(addr == map->buckets + map_cap(map));
    (void)addr; /* avoid unused warning */

    map->lcap++;

    // foreach part 1
    for (u32_t idx = 0, n = map_cap(map) >> 1; idx < n; ++idx) {
        bucket_s *head = get_bucket(map, idx);

        // ignore non-head node
        if (!bucket_is_head(head)) continue;

        // foreach list
        for (bucket_s *cur = head, *prev = NULL; cur;) {
            u32_t newidx = L2_idx(dnl, get_hashv(cur->name));

            if (newidx == idx) {
                /* still the same list pos */
                prev = cur;
                cur = next_bucket(map, cur);
            } else {
                /* must be in the part 2 */
                assert(newidx >= n);
                assert(newidx < map_cap(map));

                u32_t nameaddr = cur->name;
                u32_t nextidx = cur->next;
                bucket_s *next = next_bucket(map, cur);

                if (!prev) {
                    /* cur node is head */
                    assert(cur == head);
                    assert(bucket_is_head(head));
                    if (next) {
                        /* next_node => head */
                        head->name = next->name; // copy next node to head
                        head->next = next->next; // copy next node to head
                        free_bucket(map, next); // free next node
                    } else {
                        /* list_size == 1 (only the head) */
                        free_bucket(map, head); // free it
                        cur = NULL; // foreach end
                    }
                } else {
                    /* cur node is body */
                    assert(bucket_is_body(cur));
                    free_bucket(map, cur); // free cur node
                    prev->next = nextidx; // repair list link
                    cur = next; // foreach from here
                }

                // add to new list
                bucket_s *newhead = get_bucket(map, newidx);
                if (bucket_is_free(newhead))
                    store_as_head(newhead, nameaddr);
                else if (bucket_is_head(newhead))
                    store_as_body(map, newhead, nameaddr);
                else if (bucket_is_body(newhead))
                    change_to_head(dnl, L2, newhead, nameaddr);
                else
                    assert(0);
            }
        }
    }
}

#define try_resize_L2(dnl) ({ \
    int resized_ = 0; \
    const map_s *map_ = L2(dnl); \
    if (map_->nitems >= map_maxload(map_)) { \
        resize_L2(dnl); \
        resized_ = 1; \
    } \
    resized_; \
})

static void add_to_L2(dnl_s *dnl, u32_t nameaddr) {
    map_s *map = L2(dnl);
    if (map_is_null(map)) {
        map_set_notnull(map);
        map->lcap = DEFAULT_LCAP;
        map->buckets = alloc_bucket(map_cap(map));
    }
    bucket_s *head = L2_bucket_by_nameaddr(dnl, nameaddr);
    if (bucket_is_free(head)) {
        if (try_resize_L2(dnl))
            return add_to_L2(dnl, nameaddr);
        store_as_head(head, nameaddr);
        map->nitems++;
    } else if (bucket_is_head(head)) {
        return_if_exists(map, head, nameaddr);
        if (try_resize_L2(dnl))
            return add_to_L2(dnl, nameaddr);
        store_as_body(map, head, nameaddr);
        map->nitems++;
    } else if (bucket_is_body(head)) {
        if (try_resize_L2(dnl))
            return add_to_L2(dnl, nameaddr);
        change_to_head(dnl, L2, head, nameaddr);
        map->nitems++;
    } else {
        assert(0);
    }
}

static void add_to_dnl(dnl_s *dnl, u32_t nameaddr) {
    map_s *map = L1(dnl);
    bucket_s *head = L1_bucket_by_nameaddr(dnl, nameaddr);
    if (bucket_is_free(head)) {
        store_as_head(head, nameaddr);
        map->nitems++;
    } else if (bucket_is_head(head)) {
        int n_nodes = return_if_exists(map, head, nameaddr);
        if (n_nodes < MAX_COLLISION) {
            store_as_body(map, head, nameaddr);
            map->nitems++;
        } else {
            /* `resize_L2()` may change the pool addr. so must be foreach by idx */
            bucket_set_next(head); /* next time, find in the next-level buckets (L2) */
            u32_t headidx = idx_of_bucket(map, head);
            for (u32_t idx = headidx; idx != (u32_t)-1; idx = get_bucket(map, idx)->next) {
                map->nitems--;
                add_to_L2(dnl, get_bucket(map, idx)->name);
                if (idx != headidx) free_bucket(map, get_bucket(map, idx));
            }
            add_to_L2(dnl, nameaddr);
        }
    } else if (bucket_is_body(head)) {
        change_to_head(dnl, L1, head, nameaddr);
        map->nitems++;
    } else {
        assert(bucket_in_next(head));
        add_to_L2(dnl, nameaddr);
    }
}

#define exists_in_list(map, head, hashv, namelen, NAME) ({ \
    bool exists_ = false; \
    foreach_list(map, head, cur) { \
        if (name_eq_r(cur->name, hashv, namelen, NAME)) { \
            exists_ = true; \
            break; \
        } \
    } \
    exists_; \
})

static bool exists_in_dnl(const dnl_s *dnl, const char *name, namelen_t namelen) {
    hashv_t hashv = calc_hashv(name, namelen);
    bucket_s *head = L1_bucket_by_hashv(dnl, hashv);
    if (bucket_is_head(head)) {
        return exists_in_list(L1(dnl), head, hashv, namelen, name);
    } else if (bucket_in_next(head)) {
        head = L2_bucket_by_hashv(dnl, hashv);
        if (bucket_is_head(head))
            return exists_in_list(L2(dnl), head, hashv, namelen, name);
    }
    return false;
}

// "a.www.google.com.hk" => "www.google.com.hk"
static const char *dname_trim(const char *dname) {
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

/* used by dnl_ismatch() */
/* "a.www.google.com.hk" => ["hk", "com.hk", "google.com.hk", "www.google.com.hk"], arraylen=LABEL_MAXCNT */
static unsigned dname_split(const char *dname, unsigned dnamelen, const char *sub_dnames[], unsigned sub_dnamelens[]) {
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

    u32_t nitems = 0, addr0 = 0;
    char buf[DNS_DOMAIN_NAME_MAXLEN + 1];

    while (fscanf(fp, "%" literal(DNS_DOMAIN_NAME_MAXLEN) "s", buf) > 0) {
        const char *name = dname_trim(buf);
        if (name) {
            u32_t nameaddr = add_to_namepool(name);
            if (nitems++ == 0) addr0 = nameaddr;
        }
    }

    if (fp != stdin) fclose(fp);

    if (nitems == 0) return 0;

    dnl_s *dnl = is_gfwlist ? &g_gfwlist : &g_chnlist;

    dnl_set_notnull(dnl);
    L1(dnl)->lcap = calc_lcap(nitems);
    L1(dnl)->buckets = alloc_bucket(L1_cap(dnl));

    for (u32_t i = 0, nameaddr = addr0; i < nitems; ++i) {
        add_to_dnl(dnl, nameaddr);
        nameaddr += get_namesz(nameaddr);
    }

    return L1(dnl)->nitems + L2(dnl)->nitems;
}

/* check if the given domain name matches */
u8_t dnl_ismatch(const char *dname, bool is_gfwlist_first) {
    const char *sub_dnames[LABEL_MAXCNT];
    unsigned sub_dnamelens[LABEL_MAXCNT];

    unsigned arraylen = dname_split(dname, strlen(dname), sub_dnames, sub_dnamelens);
    if (arraylen <= 0)
        return DNL_MRESULT_NOMATCH;

    const dnl_s *dnl = is_gfwlist_first ? &g_gfwlist : &g_chnlist;
    if (!dnl_is_null(dnl)) {
        for (unsigned i = 0; i < arraylen; ++i) {
            if (exists_in_dnl(dnl, sub_dnames[i], sub_dnamelens[i]))
                return is_gfwlist_first ? DNL_MRESULT_GFWLIST : DNL_MRESULT_CHNLIST;
        }
    }

    dnl = is_gfwlist_first ? &g_chnlist : &g_gfwlist;
    if (!dnl_is_null(dnl)) {
        for (unsigned i = 0; i < arraylen; ++i) {
            if (exists_in_dnl(dnl, sub_dnames[i], sub_dnamelens[i]))
                return is_gfwlist_first ? DNL_MRESULT_CHNLIST : DNL_MRESULT_GFWLIST;
        }
    }

    return DNL_MRESULT_NOMATCH;
}
