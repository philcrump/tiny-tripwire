#include <stdint.h>
#include <stddef.h>

#include "bsearch64.h"

void *bsearch64(const void *key_ptr, void *base_ptr, int64_t num, int64_t size, int64_t (*compare)(const void *element1, const void *element2))
{
  int64_t low = 0;
  int64_t high = num;
  int64_t mid;
  int64_t result;

  while(low < high)
  {
    mid = (low + high) / 2;
    result = compare(((uint8_t*)base_ptr + (mid * size)), key_ptr);
    if(result == 0)
    {
      return ((uint8_t*)base_ptr + (mid * size));
    }
    else if(result < 0)
    {
      low = mid + 1;
    }
    else // if(c > 0)
    {
      high = mid;
    }
  }

  return NULL;
}