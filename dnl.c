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
    map_s map1;
    map_s map2;
} dnl_s;

static dnl_s s_gfwlist; // = {0};
static dnl_s s_chnlist; // = {0};

static char *s_name_pool     = NULL;
static u32_t s_name_poolcap  = 0;
static u32_t s_name_poolused = 0;

static bucket_s *s_bucket_pool     = NULL;
static u32_t     s_bucket_poolcap  = 0;
static u32_t     s_bucket_poolused = 0;

/* ======================== alloc ======================== */

#define pool(tag)     s_##tag##_pool
#define poolcap(tag)  s_##tag##_poolcap
#define poolused(tag) s_##tag##_poolused

// return addr(idx) in pool
#define pool_alloc(tag, n) ({ \
    poolused(tag) += (n); \
    if (poolcap(tag) < poolused(tag)) { \
        poolcap(tag) = poolused(tag); \
        pool(tag) = realloc(pool(tag), poolcap(tag) * sizeof(*pool(tag))); \
        if (!pool(tag)) { \
            fprintf(stderr, "can't alloc memory. tag:%s n:%lu newcap:%lu\n", #tag, (ulong)(n), (ulong)poolcap(tag)); \
            abort(); \
        } \
    } \
    poolused(tag) - (n); \
})

#define alloc_name(sz) pool_alloc(name, sz)

#define _alloc_bucket(n) pool_alloc(bucket, n)

#define alloc_bucket(n) ({ \
    u32_t addr_ = _alloc_bucket(n); \
    memset(s_bucket_pool + addr_, 0, (n) * sizeof(bucket_s)); \
    addr_; \
})

/* ======================== name ======================== */

#define calc_hashv(name, namelen) ({ \
    hashv_t hashv_ = 0; \
    HASH_FCN(name, namelen, hashv_); /* uthash.h */ \
    hashv_; \
})

#define name_base(nameaddr) (s_name_pool + (nameaddr))

#define get_hashv(nameaddr) ({ \
    hashv_t hashv_; \
    memcpy(&hashv_, name_base(nameaddr), sizeof(hashv_)); \
    hashv_; \
})

#define set_hashv(nameaddr, hashv) \
    memcpy(name_base(nameaddr), &(hashv), sizeof(hashv))

#define get_namelen(nameaddr) ({ \
    namelen_t namelen_; \
    memcpy(&namelen_, name_base(nameaddr) + sizeof(hashv_t), sizeof(namelen_)); \
    namelen_; \
})

#define set_namelen(nameaddr, namelen) \
    memcpy(name_base(nameaddr) + sizeof(hashv_t), &(namelen), sizeof(namelen))

#define get_name(nameaddr) \
    (name_base(nameaddr) + sizeof(hashv_t) + sizeof(namelen_t))

#define set_name(nameaddr, name, namelen) \
    memcpy(get_name(nameaddr), name, namelen)

#define calc_namesz(namelen) \
    (sizeof(hashv_t) + sizeof(namelen_t) + (namelen))

#define get_namesz(nameaddr) \
    calc_namesz(get_namelen(nameaddr))

#define name_to_pool(name) ({ \
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

#define map1(dnl) (&(dnl)->map1)
#define map2(dnl) (&(dnl)->map2)

#define map_is_null(map) (!(map)->notnull)
#define map_set_notnull(map) ((map)->notnull = 1)

#define dnl_is_null(dnl) map_is_null(map1(dnl))
#define dnl_set_notnull(dnl) map_set_notnull(map1(dnl))

#define map_cap(map) (1 << (map)->lcap)
#define map_maxload(map) ((u32_t)((double)map_cap(map) * LOAD_FACTOR))

#define map1_cap(dnl) map_cap(map1(dnl))
#define map2_cap(dnl) map_cap(map2(dnl))

#define map1_hashv(dnl, hashv) (hashv)
#define map2_hashv(dnl, hashv) (map1_hashv(dnl, hashv) >> map1(dnl)->lcap)

#define map1_idx(dnl, hashv) (map1_hashv(dnl, hashv) & (map1_cap(dnl) - 1))
#define map2_idx(dnl, hashv) (map2_hashv(dnl, hashv) & (map2_cap(dnl) - 1))

#define get_bucket(map, idx) (s_bucket_pool + (map)->buckets + (idx))
#define idx_of_bucket(map, bucket) ((bucket) - s_bucket_pool - (map)->buckets)
#define next_bucket(map, bucket) ((bucket)->next == (u32_t)-1 ? NULL : get_bucket(map, (bucket)->next))

#define map1_bucket_by_hashv(dnl, hashv) get_bucket(map1(dnl), map1_idx(dnl, hashv))
#define map2_bucket_by_hashv(dnl, hashv) get_bucket(map2(dnl), map2_idx(dnl, hashv))
#define map1_bucket_by_nameaddr(dnl, nameaddr) map1_bucket_by_hashv(dnl, get_hashv(nameaddr))
#define map2_bucket_by_nameaddr(dnl, nameaddr) map2_bucket_by_hashv(dnl, get_hashv(nameaddr))

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
#define change_to_head(dnl, mapN, oldbody, headnameaddr) ({ \
    /* calc oldbody idx */ \
    map_s *map_ = mapN(dnl); \
    u32_t oldbodyidx_ = idx_of_bucket(map_, oldbody); \
    assert(get_bucket(map_, oldbodyidx_) == (oldbody)); \
    /* copy from old to new */ \
    u32_t newbodyidx_ = find_free_idx(map_); \
    bucket_s *newbody_ = get_bucket(map_, newbodyidx_); \
    bucket_set_body(newbody_); \
    newbody_->name = (oldbody)->name; \
    newbody_->next = (oldbody)->next; \
    /* repair the list it is in */ \
    bucket_s *head_ = concat(mapN, _bucket_by_nameaddr(dnl, newbody_->name)); \
    assert(bucket_is_head(head_)); \
    int found_ = 0; \
    foreach_list(map_, head_, cur) { \
        if (cur->next == oldbodyidx_) { \
            cur->next = newbodyidx_; \
            found_ = 1; \
            break; \
        } \
    } \
    (void)found_; /* avoid unused warning */ \
    assert(found_); \
    /* change it to head node */ \
    store_as_head(oldbody, headnameaddr); \
})

static void resize_map2(dnl_s *dnl) {
    map_s *map = map2(dnl);

    // grow *2 (may change the pool addr)
    u32_t addr = alloc_bucket(map_cap(map));
    assert(addr == map->buckets + map_cap(map));
    (void)addr; /* avoid unused warning */

    map->lcap++;

    // foreach part 1
    for (u32_t idx = 0, n = map_cap(map) >> 1; idx < n; ++idx) {
        bucket_s *const head = get_bucket(map, idx);

        // ignore non-head node
        if (!bucket_is_head(head)) continue;

        // foreach list
        for (bucket_s *cur = head, *prev = NULL; cur;) {
            u32_t newidx = map2_idx(dnl, get_hashv(cur->name));

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

                // remove from old list
                if (!prev) {
                    /* cur node is head */
                    assert(cur == head);
                    assert(bucket_is_head(cur));
                    if (next) {
                        /* next_node => head */
                        cur->name = next->name; // copy next node to head
                        cur->next = next->next; // copy next node to head
                        free_bucket(map, next); // free next node
                    } else {
                        /* list_size == 1 (only the head) */
                        free_bucket(map, cur); // free it
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
                    change_to_head(dnl, map2, newhead, nameaddr);
                else
                    assert(0);
            }
        }
    }
}

#define try_resize_map2(dnl) ({ \
    int resized_ = 0; \
    const map_s *map_ = map2(dnl); \
    if (map_->nitems >= map_maxload(map_)) { \
        resize_map2(dnl); \
        resized_ = 1; \
    } \
    resized_; \
})

static void add_to_map2(dnl_s *dnl, u32_t nameaddr) {
    map_s *map = map2(dnl);
    if (map_is_null(map)) {
        map_set_notnull(map);
        map->lcap = DEFAULT_LCAP;
        map->buckets = alloc_bucket(map_cap(map));
    }
    bucket_s *head;
redo:
    head = map2_bucket_by_nameaddr(dnl, nameaddr);
    if (bucket_is_free(head)) {
        if (try_resize_map2(dnl)) goto redo;
        store_as_head(head, nameaddr);
        map->nitems++;
    } else if (bucket_is_head(head)) {
        return_if_exists(map, head, nameaddr);
        if (try_resize_map2(dnl)) goto redo;
        store_as_body(map, head, nameaddr);
        map->nitems++;
    } else if (bucket_is_body(head)) {
        if (try_resize_map2(dnl)) goto redo;
        change_to_head(dnl, map2, head, nameaddr);
        map->nitems++;
    } else {
        assert(0);
    }
}

static void add_to_dnl(dnl_s *dnl, u32_t nameaddr) {
    map_s *map = map1(dnl);
    bucket_s *head = map1_bucket_by_nameaddr(dnl, nameaddr);
    if (bucket_is_free(head)) {
        store_as_head(head, nameaddr);
        map->nitems++;
    } else if (bucket_is_head(head)) {
        int n_nodes = return_if_exists(map, head, nameaddr);
        if (n_nodes < MAX_COLLISION) {
            store_as_body(map, head, nameaddr);
            map->nitems++;
        } else {
            /* `resize_map2()` may change the pool addr. so must be foreach by idx */
            bucket_set_next(head); /* next time, find in the next-level buckets (map2) */
            u32_t headidx = idx_of_bucket(map, head);
            for (u32_t idx = headidx; idx != (u32_t)-1; idx = get_bucket(map, idx)->next) {
                map->nitems--;
                add_to_map2(dnl, get_bucket(map, idx)->name);
                if (idx != headidx) free_bucket(map, get_bucket(map, idx));
            }
            add_to_map2(dnl, nameaddr);
        }
    } else if (bucket_is_body(head)) {
        change_to_head(dnl, map1, head, nameaddr);
        map->nitems++;
    } else {
        assert(bucket_in_next(head));
        add_to_map2(dnl, nameaddr);
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

static bool exists_in_dnl(const dnl_s *dnl, const char *noalias name, namelen_t namelen) {
    hashv_t hashv = calc_hashv(name, namelen);
    bucket_s *head = map1_bucket_by_hashv(dnl, hashv);
    if (bucket_is_head(head)) {
        return exists_in_list(map1(dnl), head, hashv, namelen, name);
    } else if (bucket_in_next(head)) {
        head = map2_bucket_by_hashv(dnl, hashv);
        if (bucket_is_head(head))
            return exists_in_list(map2(dnl), head, hashv, namelen, name);
    }
    return false;
}

// "a.www.google.com.hk" => "www.google.com.hk"
static const char *name_trim(const char *name) {
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
static int name_split(const char *noalias name, int namelen, const char *noalias sub_names[noalias], int sub_namelens[noalias]) {
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

/* initialize domain-name-list from file */
u32_t dnl_init(const char *noalias filename, bool is_gfwlist) {
    FILE *fp = NULL;

    if (strcmp(filename, "-") == 0) {
        fp = stdin;
    } else {
        fp = fopen(filename, "rb");
        if (!fp) {
            LOGE("failed to open '%s': (%d) %s", filename, errno, strerror(errno));
            exit(errno);
        }
    }

    u32_t nitems = 0, addr0 = 0;
    char buf[DNS_NAME_MAXLEN + 1];

    while (fscanf(fp, "%" literal(DNS_NAME_MAXLEN) "s", buf) > 0) {
        const char *name = name_trim(buf);
        if (name) {
            u32_t nameaddr = name_to_pool(name);
            if (nitems++ == 0) addr0 = nameaddr;
        }
    }

    if (fp != stdin) fclose(fp);

    if (nitems == 0) return 0;

    dnl_s *dnl = is_gfwlist ? &s_gfwlist : &s_chnlist;

    dnl_set_notnull(dnl);
    map1(dnl)->lcap = calc_lcap(nitems);
    map1(dnl)->buckets = alloc_bucket(map1_cap(dnl));

    for (u32_t i = 0, nameaddr = addr0; i < nitems; ++i) {
        add_to_dnl(dnl, nameaddr);
        nameaddr += get_namesz(nameaddr);
    }

    return map1(dnl)->nitems + map2(dnl)->nitems;
}

/* check if the given domain name matches */
u8_t get_name_tag(const char *noalias name, int namelen, bool is_gfwlist_first) {
    const char *noalias sub_names[LABEL_MAXCNT];
    int sub_namelens[LABEL_MAXCNT];

    assert(namelen > 0);
    int n = name_split(name, namelen, sub_names, sub_namelens);
    assert(n > 0);

    const dnl_s *dnl = is_gfwlist_first ? &s_gfwlist : &s_chnlist;
    if (!dnl_is_null(dnl)) {
        for (int i = 0; i < n; ++i) {
            if (exists_in_dnl(dnl, sub_names[i], sub_namelens[i]))
                return is_gfwlist_first ? NAME_TAG_GFW : NAME_TAG_CHN;
        }
    }

    dnl = is_gfwlist_first ? &s_chnlist : &s_gfwlist;
    if (!dnl_is_null(dnl)) {
        for (int i = 0; i < n; ++i) {
            if (exists_in_dnl(dnl, sub_names[i], sub_namelens[i]))
                return is_gfwlist_first ? NAME_TAG_CHN : NAME_TAG_GFW;
        }
    }

    return NAME_TAG_NONE;
}
