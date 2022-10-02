#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdbool.h>

#include "config.h"
#include "incident.h"
#include "ouilist.h"

typedef struct {
  bool exit_requested;
  config_t config;

  struct in_addr *interface_v4_addresses;
  int32_t interface_v4_addresses_count;

  struct in6_addr *interface_v6_addresses;
  int32_t interface_v6_addresses_count;

  char *interface_addresses_string;

  ouilist_t ouilist;

  incident_t incident;

} app_data_t;

#endif /* __MAIN_H__ */