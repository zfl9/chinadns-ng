#pragma once

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define likely_if(x) if (likely(x))
#define unlikely_if(x) if (unlikely(x))

typedef signed char schar;
typedef unsigned char uchar;
