#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <stdbool.h>

#define CONFIG_LISTEN_PORTS_MAXCOUNT  (64)

typedef struct {
  char *listen_interface;
  bool listen_icmp;
  int32_t listen_ports[CONFIG_LISTEN_PORTS_MAXCOUNT+1];

  int32_t notification_latency_s;
  char *notification_email_source;
  char *notification_email_destination;
  char *notification_email_subject;

  bool smtp_enabled;
  bool smtp_server_usessl;
  bool smtp_server_usetls;
  bool smtp_server_verifyca;
  char *smtp_server_hostname;
  int smtp_server_port;
  bool smtp_server_useauth;
  char *smtp_server_username;
  char *smtp_server_password;
} config_t;

bool load_config(char *config_filename, config_t *config_ptr);

#endif /* __CONFIG_H__ */
