#pragma once

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define likely_if(x) if (likely(x))
#define unlikely_if(x) if (unlikely(x))

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

typedef signed char byte; /* >= 8 bits */
typedef unsigned char ubyte; /* >= 8 bits */
typedef unsigned short ushort; /* >= 16 bits */
typedef unsigned int uint; /* >= 16 bits */
typedef unsigned long ulong; /* >= 32 bits */
typedef long long llong; /* >= 64 bits */
typedef unsigned long long ullong; /* >= 64 bits */

/* to avoid breaking the constant properties of input parameters, do not use __auto_type or __typeof__ */
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/* compile-time ceil (a,b,res is integer) */
#define ceili(a, b) (((a) + (b) - 1) / (b))

/* number of elements */
#define array_n(a) (sizeof(a) / sizeof(*(a)))

#define cast(t, v) ((t)(v))

/* for blocking system calls */
#define retry_EINTR(call) ({ \
    __typeof__(call) ret_; \
    while ((ret_ = (call)) == -1 && errno == EINTR); \
    ret_; \
})

/* get arg (1 ~ 10) */
#define arg1(x, ...) (x)
#define arg2(_1, x, ...) (x)
#define arg3(_1, _2, x, ...) (x)
#define arg4(_1, _2, _3, x, ...) (x)
#define arg5(_1, _2, _3, _4, x, ...) (x)
#define arg6(_1, _2, _3, _4, _5, x, ...) (x)
#define arg7(_1, _2, _3, _4, _5, _6, x, ...) (x)
#define arg8(_1, _2, _3, _4, _5, _6, _7, x, ...) (x)
#define arg9(_1, _2, _3, _4, _5, _6, _7, _8, x, ...) (x)
#define arg10(_1, _2, _3, _4, _5, _6, _7, _8, _9, x, ...) (x)

/* get arg by literal-idx */
#define argN(idx, args...) arg##idx(args)

/* get arg count (1 ~ 9) */
#define argc(args...) arg10(args, 9, 8, 7, 6, 5, 4, 3, 2, 1)
