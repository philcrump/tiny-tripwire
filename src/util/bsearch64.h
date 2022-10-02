#ifndef __BSEARCH64_H__
#define __BSEARCH64_H__

#include <stdint.h>

void *bsearch64(const void *key_ptr, void *base_ptr, int64_t num, int64_t size, int64_t (*compare)(const void *element1, const void *element2));

#endif /* __BSEARCH64_H__ */
