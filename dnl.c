#ifdef NDEBUG
  #undef NDEBUG
#endif

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
#include <unistd.h>

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
    u32_t tag:1; // NAME_TAG_* (gfw or chn)
    u32_t name:29; // addr in pool
    u32_t next; // #list# bucket idx (-1: end)
} bucket_s;

typedef struct map {
    u32_t notnull; // map not-null
    u32_t buckets; // addr in pool
    u32_t lcap; // log2 of cap
    u32_t freeidx; // find free-bucket from here
    u32_t nitems; // nitems stored in buckets
} map_s;

u32_t g_gfwlist_cnt = 0;
u32_t g_chnlist_cnt = 0;

static map_s s_map1 = {0}; /* L1 map (<= MAX_COLLISION) */
static map_s s_map2 = {0}; /* L2 map (> MAX_COLLISION) */

static char *s_name_pool    = NULL;
static u32_t s_name_poolcap = 0;

static bucket_s *s_bucket_pool    = NULL;
static u32_t     s_bucket_poolcap = 0;

/* ======================== alloc ======================== */

#define pool(tag)     s_##tag##_pool
#define poolcap(tag)  s_##tag##_poolcap

#define sbrk_align(tag) ({ \
    size_t align_ = __alignof__(*pool(tag)); \
    uintptr_t p_ = (uintptr_t)sbrk(0); \
    size_t n_ = p_ % align_; \
    if (n_) { \
        n_ = align_ - n_; \
        p_ += n_; \
        assert(p_ % align_ == 0); \
        unlikely_if (sbrk(n_) == (void *)-1) { \
            fprintf(stderr, "can't align to %zu. tag:%s errno:%d %s", \
                align_, #tag, errno, strerror(errno)); \
            abort(); \
        } \
        assert(sbrk(0) == (void *)p_); \
    } \
    (void *)p_; \
})

// return addr in pool (idx)
#define pool_alloc(tag, n) ({ \
    if (!pool(tag)) pool(tag) = sbrk_align(tag); \
    size_t nbytes_ = (n) * sizeof(*pool(tag)); \
    void *p_ = sbrk(nbytes_); \
    unlikely_if (p_ == (void *)(-1)) { \
        fprintf(stderr, "can't alloc memory. tag:%s n:%lu bytes:%zu errno:%d %s", \
            #tag, (ulong)(n), nbytes_, errno, strerror(errno)); \
        abort(); \
    } \
    assert(p_ == pool(tag) + poolcap(tag)); \
    poolcap(tag) += (n); \
    poolcap(tag) - (n); \
})

#define alloc_name(sz) pool_alloc(name, sz)

#define _alloc_bucket(n) pool_alloc(bucket, n)

#define alloc_bucket(n) ({ \
    u32_t addr_ = _alloc_bucket(n); \
    memset(s_bucket_pool + addr_, 0, (n) * sizeof(bucket_s)); \
    addr_; \
})

/* ======================== name ======================== */

/* struct name { hashv_t hashv; namelen_t namelen; char name[]; }; */

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

/* map1/map2 is a getter, can be passed as arg to macro func */
#define map1() (&s_map1)
#define map2() (&s_map2)

#define map_is_null(map) (!map()->notnull)
#define map_set_notnull(map) (map()->notnull = 1)

#define dnl_is_null() map_is_null(map1)
#define dnl_set_notnull() map_set_notnull(map1)

#define map_nitems(map) (map()->nitems)
#define dnl_nitems() (map_nitems(map1) + map_nitems(map2))

#define map_cap(map) (1U << map()->lcap)
#define map_maxload(map) ((u32_t)((double)map_cap(map) * LOAD_FACTOR))

#define map_hashv(map, hashv) _##map##_hashv(hashv)
#define _map1_hashv(hashv) (hashv)
#define _map2_hashv(hashv) (_map1_hashv(hashv) >> map1()->lcap)

#define map_idx(map, hashv) (map_hashv(map, hashv) & (map_cap(map) - 1))

#define get_bucket(map, idx) (s_bucket_pool + map()->buckets + (idx))
#define idx_of_bucket(map, bucket) ((bucket) - s_bucket_pool - map()->buckets)
#define next_bucket(map, bucket) ((bucket)->next == (u32_t)-1 ? NULL : get_bucket(map, (bucket)->next))

#define bucket_by_hashv(map, hashv) get_bucket(map, map_idx(map, hashv))
#define bucket_by_nameaddr(map, nameaddr) bucket_by_hashv(map, get_hashv(nameaddr))

// find free idx to use (consume it)
#define find_free_idx(map) ({ \
    u32_t idx_ = map()->freeidx, n_ = map_cap(map), found_ = 0; \
    for (; idx_ < n_; ++idx_) { \
        if (bucket_is_free(get_bucket(map, idx_))) { \
            map()->freeidx = idx_ + 1; /* start here next time */ \
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
    if (idx_ < map()->freeidx) map()->freeidx = idx_; \
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

#define store_as_head(map, head, nametag, nameaddr) ({ \
    bucket_set_head(head); \
    (head)->tag = (nametag); \
    (head)->name = (nameaddr); \
    (head)->next = -1; \
})

#define store_as_body(map, head, nametag, nameaddr) ({ \
    /* find free bucket */ \
    u32_t bodyidx_ = find_free_idx(map); \
    bucket_s *body_ = get_bucket(map, bodyidx_); \
    bucket_set_body(body_); \
    body_->tag = (nametag); \
    body_->name = (nameaddr); \
    body_->next = (head)->next; \
    (head)->next = bodyidx_; \
})

/* body to new pos, store head in this pos */
#define change_to_head(map, oldbody, headnametag, headnameaddr) ({ \
    /* calc oldbody idx */ \
    u32_t oldbodyidx_ = idx_of_bucket(map, oldbody); \
    assert(get_bucket(map, oldbodyidx_) == (oldbody)); \
    /* copy from old to new */ \
    u32_t newbodyidx_ = find_free_idx(map); \
    bucket_s *newbody_ = get_bucket(map, newbodyidx_); \
    bucket_set_body(newbody_); \
    newbody_->tag = (oldbody)->tag; \
    newbody_->name = (oldbody)->name; \
    newbody_->next = (oldbody)->next; \
    /* repair the list it is in */ \
    bucket_s *head_ = bucket_by_nameaddr(map, newbody_->name); \
    assert(bucket_is_head(head_)); \
    int found_ = 0; \
    foreach_list(map, head_, cur) { \
        if (cur->next == oldbodyidx_) { \
            cur->next = newbodyidx_; \
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
    assert(addr == map2()->buckets + map_cap(map2));
    (void)addr; /* avoid unused warning */

    map2()->lcap++;

    // foreach part 1
    for (u32_t idx = 0, n = map_cap(map2) >> 1; idx < n; ++idx) {
        bucket_s *const head = get_bucket(map2, idx);

        // ignore non-head node
        if (!bucket_is_head(head)) continue;

        // foreach list
        for (bucket_s *cur = head, *prev = NULL; cur;) {
            u32_t newidx = map_idx(map2, get_hashv(cur->name));

            if (newidx == idx) {
                /* still the same list pos */
                prev = cur;
                cur = next_bucket(map2, cur);
            } else {
                /* must be in the part 2 */
                assert(newidx >= n);
                assert(newidx < map_cap(map2));

                u8_t nametag = cur->tag;
                u32_t nameaddr = cur->name;
                u32_t nextidx = cur->next;
                bucket_s *next = next_bucket(map2, cur);

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
                    prev->next = nextidx; // repair list link
                    cur = next; // foreach from here
                }

                // add to new list
                bucket_s *newhead = get_bucket(map2, newidx);
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
    if (map_is_null(map2)) {
        map_set_notnull(map2);
        map2()->lcap = DEFAULT_LCAP;
        map2()->buckets = alloc_bucket(map_cap(map2));
    }
    bucket_s *head;
redo:
    head = bucket_by_nameaddr(map2, nameaddr);
    if (bucket_is_free(head)) {
        if (try_resize_map2()) goto redo;
        store_as_head(map2, head, nametag, nameaddr);
        map2()->nitems++;
    } else if (bucket_is_head(head)) {
        return_if_exists(map2, head, nameaddr);
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
    bucket_s *head = bucket_by_nameaddr(map1, nameaddr);
    if (bucket_is_free(head)) {
        store_as_head(map1, head, nametag, nameaddr);
        map1()->nitems++;
    } else if (bucket_is_head(head)) {
        int n_nodes = return_if_exists(map1, head, nameaddr);
        if (n_nodes < MAX_COLLISION) {
            store_as_body(map1, head, nametag, nameaddr);
            map1()->nitems++;
        } else {
            /* `resize_map2()` may change the pool addr. so must be foreach by idx */
            bucket_set_next(head); /* next time, find in the next-level buckets (map2) */
            u32_t headidx = idx_of_bucket(map1, head);
            for (u32_t idx = headidx; idx != (u32_t)-1; idx = get_bucket(map1, idx)->next) {
                map1()->nitems--;
                add_to_map2(get_bucket(map1, idx)->tag, get_bucket(map1, idx)->name);
                if (idx != headidx) free_bucket(map1, get_bucket(map1, idx));
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

#define exists_in_list(map, head, hashv, namelen, NAME, p_tag) ({ \
    bool exists_ = false; \
    foreach_list(map, head, cur) { \
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
    bucket_s *head = bucket_by_hashv(map1, hashv);
    if (bucket_is_head(head)) {
        return exists_in_list(map1, head, hashv, namelen, name, p_tag);
    } else if (bucket_in_next(head)) {
        head = bucket_by_hashv(map2, hashv);
        if (bucket_is_head(head))
            return exists_in_list(map2, head, hashv, namelen, name, p_tag);
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

static bool load_list(const char *noalias filename, u32_t *noalias p_addr0, u32_t *noalias p_nitems) {
    FILE *fp = NULL;

    if (strcmp(filename, "-") == 0) {
        fp = stdin;
    } else {
        fp = fopen(filename, "rb");
        if (!fp) {
            LOGE("failed to open '%s': (%d) %s", filename, errno, strerror(errno));
            return false;
        }
    }

    u32_t addr0 = 0, nitems = 0;
    char buf[DNS_NAME_MAXLEN + 1];

    while (fscanf(fp, "%" literal(DNS_NAME_MAXLEN) "s", buf) > 0) {
        const char *name = name_trim(buf);
        if (name) {
            u32_t nameaddr = name_to_pool(name);
            if (nitems++ == 0) addr0 = nameaddr;
        }
    }

    if (fp != stdin) fclose(fp);

    if (nitems <= 0) return false;

    *p_addr0 = addr0;
    *p_nitems = nitems;

    return true;
}

static u32_t add_list(u8_t nametag, u32_t addr0, u32_t nitems) {
    u32_t old_cnt = dnl_nitems();
    for (u32_t i = 0, nameaddr = addr0; i < nitems; ++i) {
        add_to_dnl(nametag, nameaddr);
        nameaddr += get_namesz(nameaddr);
    }
    return dnl_nitems() - old_cnt;
}

/* initialize domain-name-list from file */
void dnl_init(void) {
    u32_t gfw_addr0 = 0, gfw_nitems = 0;
    bool has_gfw = g_gfwlist_fname && load_list(g_gfwlist_fname, &gfw_addr0, &gfw_nitems);

    u32_t chn_addr0 = 0, chn_nitems = 0;
    bool has_chn = g_chnlist_fname && load_list(g_chnlist_fname, &chn_addr0, &chn_nitems);

    if (!has_gfw && !has_chn) return;

    /* first load_list() and then add_list() is friendly to malloc/realloc */

    dnl_set_notnull();
    map1()->lcap = calc_lcap(gfw_nitems + chn_nitems);
    map1()->buckets = alloc_bucket(map_cap(map1));

    if (has_gfw && has_chn) {
        if (g_gfwlist_first) {
            g_gfwlist_cnt = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
            g_chnlist_cnt = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
        } else {
            g_chnlist_cnt = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
            g_gfwlist_cnt = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
        }
    } else if (has_gfw) {
        g_gfwlist_cnt = add_list(NAME_TAG_GFW, gfw_addr0, gfw_nitems);
    } else {
        assert(has_chn);
        g_chnlist_cnt = add_list(NAME_TAG_CHN, chn_addr0, chn_nitems);
    }
}

/* check if the given domain name matches */
u8_t get_name_tag(const char *noalias name, int namelen) {
    assert(!dnl_is_null());

    const char *noalias sub_names[LABEL_MAXCNT];
    int sub_namelens[LABEL_MAXCNT];

    assert(namelen > 0);
    int n = name_split(name, namelen, sub_names, sub_namelens);
    assert(n > 0);

    u8_t name_tag;
    for (int i = 0; i < n; ++i) {
        if (exists_in_dnl(sub_names[i], sub_namelens[i], &name_tag))
            return name_tag;
    }

    return NAME_TAG_NONE;
}
