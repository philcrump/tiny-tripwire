#ifndef __OUILIST_H__
#define __OUILIST_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  uint64_t macaddr_integer;
  uint32_t macaddr_mask;
  char *macaddr_string;
  char *name_string;
} ouilist_entry_t;

typedef struct {
  bool loaded;
  int32_t entries_count;
  ouilist_entry_t *entries;
} ouilist_t;

bool oui_loadfile(ouilist_t *ouilist_ptr, char *ouilist_filename);

bool oui_lookup(ouilist_t *ouilist_ptr, char *target_macaddr, char *response_buffer, int32_t response_buffer_length);

#endif /* __OUILIST_H__ */
