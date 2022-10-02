#ifndef __INCIDENT_H__
#define __INCIDENT_H__

#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>

#include "sniff.h"

typedef struct {
  uint64_t timestamp_ms;
  struct in_addr src_addr;
  uint8_t src_mac[ETHER_ADDR_LEN];
  uint8_t ip_proto;
  uint16_t src_port; // TCP
  uint16_t dst_port; // TCP
  uint8_t tcp_th_flags;
} incident_entry_t;

typedef struct {
  pthread_mutex_t lock;

  bool active;
  uint64_t starttime_ms;
  int32_t entries_count;
  incident_entry_t *entries;
} incident_t;

#endif /* __INCIDENT_H__ */
