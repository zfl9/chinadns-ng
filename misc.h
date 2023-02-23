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
