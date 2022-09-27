#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdbool.h>

#include "config.h"
#include "incident.h"

typedef struct {
  bool exit_requested;
  config_t config;

  incident_t incident;

} app_data_t;

#endif /* __MAIN_H__ */