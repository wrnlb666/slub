#include "slub.h"

#define CACHE_SIZE_MIN (64)
#define CACHE_SIZE_MAX (4096)

typedef enum {
    CacheSize64,
    CacheSize128,
    CacheSize256,
    CacheSize512,
    CacheSize1024,
    CacheSize2048,
    CacheSize4096,
    CacheSizeCount,
} CacheSize;

#define BLOCK_SIZE     (2097152)  // 2 MB
#define BLOCK_CAP_64   (29126)    // ((2 MB) - sizeof (Block(meta))) / (8 + 64)
#define BLOCK_CAP_128  (15420)    // ((2 MB) - sizeof (Block(meta))) / (8 + 128)
#define BLOCK_CAP_256  (7943)     // ((2 MB) - sizeof (Block(meta))) / (8 + 256)
#define BLOCK_CAP_512  (4032)     // ((2 MB) - sizeof (Block(meta))) / (8 + 512)
#define BLOCK_CAP_1024 (2032)     // ((2 MB) - sizeof (Block(meta))) / (8 + 1024)
#define BLOCK_CAP_2048 (1020)     // ((2 MB) - sizeof (Block(meta))) / (8 + 2048)
#define BLOCK_CAP_4096 (510)      // ((2 MB) - sizeof (Block(meta))) / (8 + 4096)

typedef struct Block Block;

#define DEFINE_DATA_NODE(size)            \
    typedef struct Data##size Data##size; \
    struct Data##size {                   \
        union {                           \
            Data##size* next;             \
            Block*      block;            \
        };                                \
        char data[size];                  \
    };

DEFINE_DATA_NODE(64)
DEFINE_DATA_NODE(128)
DEFINE_DATA_NODE(256)
DEFINE_DATA_NODE(512)
DEFINE_DATA_NODE(1024)
DEFINE_DATA_NODE(2048)
DEFINE_DATA_NODE(4096)

struct Block {
    CacheSize type;
    uint32_t  size;
    void*     curr;
    union {
        Data64   data64[BLOCK_CAP_64];
        Data128  data128[BLOCK_CAP_128];
        Data256  data256[BLOCK_CAP_256];
        Data512  data512[BLOCK_CAP_512];
        Data1024 data1024[BLOCK_CAP_1024];
        Data2048 data2048[BLOCK_CAP_2048];
        Data4096 data4096[BLOCK_CAP_4096];
    };
};

#define CACHE_BLOCK_CAP (2048)

typedef struct Cache Cache;
struct Cache {
    struct {
        uint32_t len;
        Block*   block[CACHE_BLOCK_CAP];
    } free_block[CacheSizeCount];
};

static thread_local Cache cache = {};

void* slub_pg_alloc(size_t size);
void  slub_pg_free(void* ptr, size_t size);

#define DEFINE_BLOCK_INIT_SIZE(sz)                             \
    static Block* block_init_##sz(void) {                      \
        Block* block = slub_pg_alloc(BLOCK_SIZE);              \
        block->type = CacheSize##sz;                           \
        block->size = 0;                                       \
        block->curr = block->data##sz;                         \
        for (int i = 0; i < BLOCK_CAP_##sz - 1; i++) {         \
            block->data##sz[i].next = &block->data##sz[i + 1]; \
        }                                                      \
        block->data64[BLOCK_CAP_##sz - 1].next = NULL;         \
        return block;                                          \
    }

DEFINE_BLOCK_INIT_SIZE(64)
DEFINE_BLOCK_INIT_SIZE(128)
DEFINE_BLOCK_INIT_SIZE(256)
DEFINE_BLOCK_INIT_SIZE(512)
DEFINE_BLOCK_INIT_SIZE(1024)
DEFINE_BLOCK_INIT_SIZE(2048)
DEFINE_BLOCK_INIT_SIZE(4096)

static Block* (*block_init_size_funcs[])() = {
    [CacheSize64] = block_init_64,
    [CacheSize128] = block_init_128,
    [CacheSize256] = block_init_256,
    [CacheSize512] = block_init_512,
    [CacheSize1024] = block_init_1024,
    [CacheSize2048] = block_init_2048,
    [CacheSize4096] = block_init_4096,
};

static Block* block_init(CacheSize cs) {
    return block_init_size_funcs[cs]();
}

static void block_deinit(Block* block) {
    slub_pg_free(block, BLOCK_SIZE);
}

static CacheSize slub_trim_size(size_t size) {
    size_t    res = CACHE_SIZE_MIN;
    CacheSize sz = CacheSize64;
    while (res <= size) {
        res *= 2;
        sz += 1;
    }
    return sz;
}

static size_t slub_translate_size(CacheSize size) {
    switch (size) {
        case CacheSize64:
            return 64;
            break;
        case CacheSize128:
            return 128;
            break;
        case CacheSize256:
            return 256;
            break;
        case CacheSize512:
            return 512;
            break;
        case CacheSize1024:
            return 1024;
            break;
        case CacheSize2048:
            return 2048;
            break;
        case CacheSize4096:
            return 4096;
            break;
        default:
            return 0;
    }
}

#define DEFINE_SLUB_ALLOC_SIZE(sz)                                                         \
    static void* slub_alloc_##sz() {                                                       \
        if (cache.free_block[CacheSize##sz].len == 0) {                                    \
            cache.free_block[CacheSize##sz]                                                \
                .block[cache.free_block[CacheSize##sz].len++] = block_init(CacheSize##sz); \
        }                                                                                  \
        Block* block = cache.free_block[CacheSize##sz]                                     \
                           .block[cache.free_block[CacheSize##sz].len - 1];                \
        Data##sz* res = block->curr;                                                       \
        block->curr = res->next;                                                           \
        block->size += 1;                                                                  \
        res->block = block;                                                                \
        if (block->size == BLOCK_CAP_##sz) {                                               \
            cache.free_block[CacheSize##sz].len -= 1;                                      \
        }                                                                                  \
        return res->data;                                                                  \
    }

DEFINE_SLUB_ALLOC_SIZE(64)
DEFINE_SLUB_ALLOC_SIZE(128)
DEFINE_SLUB_ALLOC_SIZE(256)
DEFINE_SLUB_ALLOC_SIZE(512)
DEFINE_SLUB_ALLOC_SIZE(1024)
DEFINE_SLUB_ALLOC_SIZE(2048)
DEFINE_SLUB_ALLOC_SIZE(4096)

static void* (*slub_alloc_size_funcs[])() = {
    [CacheSize64] = slub_alloc_64,
    [CacheSize128] = slub_alloc_128,
    [CacheSize256] = slub_alloc_256,
    [CacheSize512] = slub_alloc_512,
    [CacheSize1024] = slub_alloc_1024,
    [CacheSize2048] = slub_alloc_2048,
    [CacheSize4096] = slub_alloc_4096,
};

void* slub_alloc(size_t size) {
    if (size > CACHE_SIZE_MAX) {
        intptr_t* ptr = slub_pg_alloc(size + sizeof(intptr_t));
        *ptr = -(size + sizeof(intptr_t));
        return &ptr[1];
    }
    CacheSize sz = slub_trim_size(size);
    return slub_alloc_size_funcs[sz]();
}

#define DEFINE_SLUB_FREE_SIZE(sz)                                                                                                            \
    static void slub_free_##sz(void* data, Block* block) {                                                                                   \
        Data##sz* ptr = data;                                                                                                                \
        if (block->size == BLOCK_CAP_##sz) {                                                                                                 \
            cache.free_block[CacheSize##sz]                                                                                                  \
                .block[cache.free_block[CacheSize##sz].len++] = block;                                                                       \
        }                                                                                                                                    \
        block->size -= 1;                                                                                                                    \
        ptr->next = block->curr;                                                                                                             \
        if (block->size == 0) {                                                                                                              \
            for (uint32_t i = 0; i < cache.free_block[CacheSize##sz].len; i++) {                                                             \
                if (cache.free_block[CacheSize##sz].block[i]->size == 0) {                                                                   \
                    block_deinit(cache.free_block[CacheSize##sz].block[i]);                                                                  \
                    cache.free_block[CacheSize##sz].block[i] = cache.free_block[CacheSize##sz].block[--cache.free_block[CacheSize##sz].len]; \
                    break;                                                                                                                   \
                }                                                                                                                            \
            }                                                                                                                                \
        }                                                                                                                                    \
    }

DEFINE_SLUB_FREE_SIZE(64)
DEFINE_SLUB_FREE_SIZE(128)
DEFINE_SLUB_FREE_SIZE(256)
DEFINE_SLUB_FREE_SIZE(512)
DEFINE_SLUB_FREE_SIZE(1024)
DEFINE_SLUB_FREE_SIZE(2048)
DEFINE_SLUB_FREE_SIZE(4096)

static void (*slub_free_size_funcs[])(void*, Block*) = {
    [CacheSize64] = slub_free_64,
    [CacheSize128] = slub_free_128,
    [CacheSize256] = slub_free_256,
    [CacheSize512] = slub_free_512,
    [CacheSize1024] = slub_free_1024,
    [CacheSize2048] = slub_free_2048,
    [CacheSize4096] = slub_free_4096,
};

void slub_free(void* ptr) {
    if (ptr == NULL) {
        return;
    }
    intptr_t* size = &((intptr_t*)ptr)[-1];
    if (*size < 0) {
        slub_pg_free(size, -*size);
        return;
    }
    Block* block = (void*)*size;
    slub_free_size_funcs[block->type](ptr, block);
}

void* slub_calloc(size_t nmemb, size_t size) {
    return slub_alloc(nmemb * size);
}

void* slub_realloc(void* ptr, size_t size) {
    if (ptr == NULL) {
        return slub_alloc(size);
    }
    if (size == 0) {
        slub_free(ptr);
        return NULL;
    }
    intptr_t ssize = ((intptr_t*)ptr)[-1];
    size_t   old_size;
    if (ssize < 0) {
        old_size = -ssize;
    } else {
        Block* block = (void*)ssize;
        old_size = slub_translate_size(block->type);
    }
    if (old_size >= size) {
        return ptr;
    }
    char* res = slub_alloc(size);
    char* old = ptr;
    for (size_t i = 0; i < old_size; i++) {
        res[i] = old[i];
    }
    slub_free(ptr);
    return res;
}

#ifdef SLUB_DEBUG
void* slub_pg_alloc(size_t size) {
    return malloc(size);
}

void slub_pg_free(void* ptr, size_t size) {
    (void)size;
    free(ptr);
}
#endif  // SLUB_DEBUG

#if !defined(SLUB_DEBUG) && defined(__linux__)
#    include <sys/mman.h>
/*#    include <valgrind/valgrind.h>*/

void* slub_pg_alloc(size_t size) {
    void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /*VALGRIND_MALLOCLIKE_BLOCK(ptr, size, 0, 0);*/
    return ptr;
}

void slub_pg_free(void* ptr, size_t size) {
    /*VALGRIND_FREELIKE_BLOCK(ptr, 0);*/
    munmap(ptr, size);
}

void* malloc(size_t size) {
    return slub_alloc(size);
}

void* calloc(size_t nmemb, size_t size) {
    return slub_calloc(nmemb, size);
}

void* realloc(void* ptr, size_t size) {
    return slub_realloc(ptr, size);
}

void free(void* ptr) {
    slub_free(ptr);
}
#endif  // __linux__
