#ifndef __INCIDENT_H__
#define __INCIDENT_H__

#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>

#include "sniff.h"

typedef struct {
  uint64_t timestamp_ms;
  uint8_t ip_version; // 4 or 6
  void *src_addr_ptr; // either (struct in_addr) or (struct in_addr6) depending on ip_version
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
