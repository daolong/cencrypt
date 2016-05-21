#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#define LOGV 0

#if 1
#define DEBUG(args...) fprintf(stderr, args)
#else
#define DEBUG(...)
#endif

#define DERROR(args...) fprintf(stderr, args)
#define DTRACE(args...) fprintf(stderr, args)

#ifndef DO_MALLOC
#define DO_MALLOC(s) malloc(s)
#endif
#ifndef DO_REALLOC
#define DO_REALLOC(p, s) realloc((void*)(p), (s))
#endif
#ifndef DO_FREE
#define DO_FREE(x) free((void*)(x))
#endif
#ifndef DO_STRDUP
#define DO_STRDUP(x) strdup((const char*)(x))
#endif

#ifndef DO_MEMCPY
#define DO_MEMCPY(d, s, l) memcpy((void*)(d), (void*)(s), (l))
#endif

#define DO_CLEAR(p,v,c) memset((void*)(p), (v), (c))

#endif /*__COMMON_H__*/