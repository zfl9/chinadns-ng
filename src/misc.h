#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <signal.h>

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define likely_if(x) if (likely(x))
#define unlikely_if(x) if (unlikely(x))

#define STATIC_ASSERT(expr) _Static_assert(expr, #expr)

/*
  void f(int n, int *noalias p, int *noalias q, const int *noalias a, const int *noalias b) {
    for (int i = 0; i < n; ++i) {
      p[i] = a[i] + b[i]
      q[i] = a[i] * b[i]
    }
  }
  p is not allowed to be aliased
  q is not allowed to be aliased
  a and b can be aliases for each other
  ==================================================
  strict aliasing: an object can only be aliased by "compatible type" or "char type"
*/
#define noalias restrict

/* ======================================================== */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define U8C  UINT8_C
#define U16C UINT16_C
#define U32C UINT32_C
#define U64C UINT64_C

#define I8C  INT8_C
#define I16C INT16_C
#define I32C INT32_C
#define I64C INT64_C

typedef signed char ibyte; /* >= 8 bits */
typedef unsigned char ubyte; /* >= 8 bits */
typedef unsigned short ushort; /* >= 16 bits */
typedef unsigned int uint; /* >= 16 bits */
typedef unsigned long ulong; /* >= 32 bits */
typedef long long llong; /* >= 64 bits */
typedef unsigned long long ullong; /* >= 64 bits */

/* ======================================================== */

/* token stringize */
#define _literal(x) #x
#define literal(x) _literal(x)

/* to avoid breaking the constant properties of input parameters, do not use __auto_type or __typeof__ */
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/* unsigned-integer variant: ceil(a / b) */
#define ceilu(a, b) (((ullong)(a) + (ullong)(b) - 1) / (ullong)(b))

/* number of elements */
#define array_n(a) (sizeof(a) / sizeof(*(a)))

#define cast(t, v) ((t)(v))

/* ======================================================== */

/* for blocking system calls */
#define retry_EINTR(call) ({ \
    __typeof__(call) ret_; \
    while ((ret_ = (call)) == -1 && errno == EINTR); \
    ret_; \
})

/* try to (blocking) send all, retry if interrupted by signal */
#define sendall(f, fd, base, len, args...) ({ \
    __typeof__(f(fd, base, len, ##args)) nsent_ = 0; \
    __auto_type base_ = (base); \
    __typeof__(nsent_) len_ = (len); \
    assert(len_ > 0); \
    do { \
        __auto_type ret_ = retry_EINTR(f(fd, &base_[nsent_], len_ - nsent_, ##args)); \
        unlikely_if (ret_ < 0) break; /* error occurs */ \
        assert(ret_ != 0); \
        nsent_ += ret_; \
    } while (nsent_ < len_); \
    nsent_ == 0 ? (__typeof__(nsent_))-1 : nsent_; \
})

/* ======================================================== */

typedef u8 bitvec_t;

#define bitvec_n(nbits) ceilu(nbits, 8)

#define bitvec_get(vec, i) \
    (!!((vec)[(ullong)(i) >> 3] & (1U << ((ullong)(i) & 7))))

#define bitvec_set1(vec, i) \
    ((vec)[(ullong)(i) >> 3] |= (1U << ((ullong)(i) & 7)))

#define bitvec_set0(vec, i) \
    ((vec)[(ullong)(i) >> 3] &= ~(1U << ((ullong)(i) & 7)))

/* ======================================================== */

/* align to `n` (struct, struct member) */
#define struct_alignto(n) \
    __attribute__((packed, aligned(n)))

/* ======================================================== */

void sig_register(int sig, sighandler_t handler);

const void *SIG_IGNORE(void);
const void *SIG_DEFAULT(void);

bool is_dir(const char *path);

ssize_t fstat_size(int fd);

uint calc_hashv(const void *ptr, size_t len);

bool has_aes(void);

u64 monotime(void);
