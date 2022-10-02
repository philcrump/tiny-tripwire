#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#include "main.h"
#include "ouilist.h"
#include "util/bsearch64.h"

static inline uint8_t HexcharToInt(char hexchar)
{
  if(hexchar >= '0' && hexchar <= '9')
  {
    return (hexchar - '0');
  }
  else if(hexchar >= 'a' && hexchar <='f')
  {
    return (hexchar - 'a' + 10);
  }
  else if(hexchar >= 'A' && hexchar <='F')
  {
    return (hexchar - 'A' + 10);
  }
  else
  {
    return 0;
  }
}

static inline uint64_t macaddrToInteger(char *macaddr_buffer, int32_t macaddr_buffer_length)
{
  uint64_t macaddr_integer = 0;
  int32_t macaddr_nibbles = 0;

  for(int32_t i = 0; i < macaddr_buffer_length; i++)
  {
    if(macaddr_buffer[i] != ':')
    {
      macaddr_nibbles++;
      macaddr_integer <<= 4;
      macaddr_integer += HexcharToInt(macaddr_buffer[i]);
    }
  }
  /* Complete bitshifts for all 6 octets even if input string is short */
  while(macaddr_nibbles++ < 12)
  {
    macaddr_integer <<= 4;
  }

  return macaddr_integer;
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define BIT_MASK(a) ((~ 0UL) << (sizeof(0UL)*8-(a)))

static inline int64_t entry_cmpfunc(const void * a, const void * b)
{
  uint64_t bitmask_common = MIN(((ouilist_entry_t*)a)->macaddr_mask, ((ouilist_entry_t*)b)->macaddr_mask);

  return 
    ( ((ouilist_entry_t*)a)->macaddr_integer & BIT_MASK(16+bitmask_common) )
    - 
    ( ((ouilist_entry_t*)b)->macaddr_integer & BIT_MASK(16+bitmask_common) );
}

bool oui_loadfile(ouilist_t *ouilist_ptr, char *ouilist_filename)
{
  /* TODO: destroy and reload from file if so? */
  if(ouilist_ptr->loaded == true)
  {
    fprintf(stderr, "[oui_loadfile] Warning; list already loaded, aborting.\n");
    return true;
  }

  FILE *oui_fileptr;

  oui_fileptr = fopen(ouilist_filename,"r");

  if(oui_fileptr == NULL)
  {
    return false;
  }

  char line[512];
  uint32_t line_length;

  /* Count lines */
  int32_t line_count = 0;
  uint32_t c_idx;

  while(fgets(line, sizeof(line), oui_fileptr) != NULL)
  {
    line_length = strlen(line);

    /* Check if line length is too short to contain useful data */
    if(line_length < 5)
    {
      continue;
    }

    /* Check if first non-whitespace character is '#', indicating a commented line */
    c_idx = 0;
    while(isspace(line[c_idx]) && c_idx < (line_length - 1))
    {
      c_idx++;
    }
    if(line[c_idx] == '#')
    {
      continue;
    }

    line_count++;
  }
  rewind(oui_fileptr);

  char *token;
  char *delim = "\t";

  /* Allocate list of at least the size we need */
  ouilist_ptr->entries = malloc(line_count * sizeof(ouilist_entry_t));
  ouilist_ptr->entries_count = 0;

  ouilist_entry_t *entry_ptr;

  while(fgets(line, sizeof(line), oui_fileptr) != NULL)
  {
    line_length = strlen(line);

    /* Check if line length is too short to contain useful data */
    if(line_length < 5)
    {
      continue;
    }

    /* Check if first non-whitespace character is '#', indicating a commented line */
    c_idx = 0;
    while(isspace(line[c_idx]) && c_idx < (line_length - 1))
    {
      c_idx++;
    }
    if(line[c_idx] == '#')
    {
      continue;
    }

    /* Trim whitespace from end of line (including newlines) */
    while(isspace(line[line_length-1]))
    {
      line_length--;
    }
    line[line_length] = '\0';

    /* Parse line as TSV */
    token = strtok(line, delim);

    if(token == NULL)
    {
      continue;
    }

    entry_ptr = &ouilist_ptr->entries[ouilist_ptr->entries_count];

    entry_ptr->macaddr_string = strdup(token);
    for(c_idx = 0; entry_ptr->macaddr_string != NULL && c_idx < strlen(entry_ptr->macaddr_string); c_idx++)
    {
      entry_ptr->macaddr_string[c_idx] = tolower(entry_ptr->macaddr_string[c_idx]);
    }

    token = strtok(NULL, delim);

    entry_ptr->name_string = strdup(token);

    if(entry_ptr->name_string != NULL &&
      0 == strcmp(entry_ptr->name_string, "IEEERegi"))
    {
      /* Netmask-Set parent entry - ignore */
      free(entry_ptr->macaddr_string);
      free(entry_ptr->name_string);
      continue;
    }

    token = strtok(NULL, delim);

    if(token != NULL)
    {
      free(entry_ptr->name_string);
      entry_ptr->name_string = strdup(token);
    }

    token = strtok(entry_ptr->macaddr_string, "/");
    token = strtok(NULL, "/");
    if(token == NULL)
    {
      /* Raw MAC address, derive mask from string length */
      int32_t mac_stringlength = strlen(entry_ptr->macaddr_string);

      if(mac_stringlength == 2) // eg. "FE"
      {
        entry_ptr->macaddr_mask = 8;
      }
      else if(mac_stringlength == 5) // eg. "FE:01"
      {
        entry_ptr->macaddr_mask = 16;
      }
      else if(mac_stringlength == 8) // eg. "FE:01:3E"
      {
        entry_ptr->macaddr_mask = 24;
      }
      else if(mac_stringlength == 11) // eg. "FE:01:3E:4D"
      {
        entry_ptr->macaddr_mask = 32;
      }
      else if(mac_stringlength == 14) // eg. "FE:01:3E:4D:AA"
      {
        entry_ptr->macaddr_mask = 32;
      }
      else if(mac_stringlength == 17) // eg. "FE:01:3E:4D:AA:B3"
      {
        entry_ptr->macaddr_mask = 48;
      }
    }
    else
    {
      /* Has explicit mask */
      entry_ptr->macaddr_mask = atoi(token);
    }

    entry_ptr->macaddr_integer = macaddrToInteger(entry_ptr->macaddr_string, strlen(entry_ptr->macaddr_string));

    ouilist_ptr->entries_count++;
  }

  fclose(oui_fileptr);

  /* Resize (reduce) buffer from original estimate */
  ouilist_ptr->entries = realloc(ouilist_ptr->entries, ouilist_ptr->entries_count * sizeof(ouilist_entry_t));

  ouilist_ptr->loaded = true;

  return true;
}

bool oui_lookup(ouilist_t *ouilist_ptr, char *target_macaddr, char *response_buffer, int32_t response_buffer_length)
{
  if(target_macaddr == NULL)
  {
    return false;
  }
  if(ouilist_ptr->loaded == false)
  {
    return false;
  }

  ouilist_entry_t search_key;

  search_key.macaddr_string = target_macaddr;
  search_key.macaddr_integer = macaddrToInteger(search_key.macaddr_string, strlen(search_key.macaddr_string));
  search_key.macaddr_mask = 48;

  ouilist_entry_t *item_ptr;

  item_ptr = (ouilist_entry_t*)bsearch64(&search_key, ouilist_ptr->entries, ouilist_ptr->entries_count, sizeof(ouilist_entry_t), entry_cmpfunc);

  if(item_ptr == NULL)
  {
    return false;
  }
  
  snprintf(response_buffer, response_buffer_length, "%s", item_ptr->name_string);
  return true;
}