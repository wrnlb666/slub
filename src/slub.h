#ifndef __STUB_H__
#define __STUB_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void* slub_alloc(size_t size);
void* slub_calloc(size_t nmemb, size_t size);
void* slub_realloc(void* ptr, size_t size);
void  slub_free(void* ptr);

#endif  // __STUB_H__
