#pragma once

#define NO_WOLFSSL_SERVER
#define WOLFSSL_NO_ATOMICS
#define WOLFSSL_AEAD_ONLY
#define LARGE_STATIC_BUFFERS
#define WOLFSSL_JNI /* ssl->data (void *) */
#define HAVE_EXT_CACHE /* new session callback */
