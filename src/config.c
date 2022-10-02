#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <uuid/uuid.h>

#include <json-c/json.h>

#include "config.h"

bool load_config(char *config_filename, config_t *config_ptr)
{
  int config_file_fd;
  char *config_file_mmap;
  struct stat config_file_st;
  struct json_object *config_obj;

  config_file_fd = open(config_filename, O_RDONLY);
  if(config_file_fd < 0)
  {
    return false;
  }

  /* Initialise mmap from config file */
  fstat(config_file_fd, &config_file_st);
  config_file_mmap = mmap(NULL, config_file_st.st_size, PROT_READ, MAP_PRIVATE, config_file_fd, 0);

  close(config_file_fd);

  config_obj = json_tokener_parse(config_file_mmap);

  if(json_object_get_type(config_obj) != json_type_object)
  {
    /* Config file not parsed correctly, should be a large object */
    munmap(config_file_mmap, config_file_st.st_size);
    return false;
  }

  struct json_object *config_obj_ptr;

  struct json_object *config_listen_obj;
  if(json_object_object_get_ex(config_obj, "listen", &config_listen_obj))
  {
    config_obj_ptr = json_object_object_get(config_listen_obj, "interface");
    config_ptr->listen_interface = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_listen_obj, "icmp");
    config_ptr->listen_icmp = json_object_get_boolean(config_obj_ptr);

    struct json_object *config_ports_array = json_object_object_get(config_listen_obj, "ports");
    int32_t config_ports_array_length = json_object_array_length(config_ports_array);
    int32_t config_ports_array_index;
    for(config_ports_array_index = 0; (config_ports_array_index < config_ports_array_length) && (config_ports_array_index < CONFIG_LISTEN_PORTS_MAXCOUNT); config_ports_array_index++)
    {
      config_obj_ptr = json_object_array_get_idx(config_ports_array, config_ports_array_index);
      config_ptr->listen_ports[config_ports_array_index] = json_object_get_int(config_obj_ptr);
    }
    for(; config_ports_array_index < CONFIG_LISTEN_PORTS_MAXCOUNT; config_ports_array_index++)
    {
      config_ptr->listen_ports[config_ports_array_index] = 0;
    }
    /* '0' terminator */
    config_ptr->listen_ports[CONFIG_LISTEN_PORTS_MAXCOUNT] = 0;

    config_obj_ptr = json_object_object_get(config_listen_obj, "ignore_local_source");
    config_ptr->listen_ignore_local_source = json_object_get_boolean(config_obj_ptr);
  }
  else
  {
    json_object_put(config_obj);
    munmap(config_file_mmap, config_file_st.st_size);
    return false;
  }

  struct json_object *config_notification_obj;
  if(json_object_object_get_ex(config_obj, "notification", &config_notification_obj))
  {
    config_obj_ptr = json_object_object_get(config_notification_obj, "latency_seconds");
    config_ptr->notification_latency_s = json_object_get_int(config_obj_ptr);

    config_obj_ptr = json_object_object_get(config_notification_obj, "email_source");
    config_ptr->notification_email_source = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_notification_obj, "email_destination");
    config_ptr->notification_email_destination = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_notification_obj, "email_subject");
    config_ptr->notification_email_subject = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_notification_obj, "ouilist_filename");
    config_ptr->notification_ouilist_filename = strdup(json_object_get_string(config_obj_ptr));
  }

  struct json_object *config_email_obj;
  if(json_object_object_get_ex(config_obj, "smtp", &config_email_obj))
  {
    config_ptr->smtp_enabled = true;

    config_obj_ptr = json_object_object_get(config_email_obj, "hostname");
    config_ptr->smtp_server_hostname = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_email_obj, "port");
    config_ptr->smtp_server_port = json_object_get_int(config_obj_ptr);

    config_obj_ptr = json_object_object_get(config_email_obj, "usessl");
    config_ptr->smtp_server_usessl = json_object_get_boolean(config_obj_ptr);

    config_obj_ptr = json_object_object_get(config_email_obj, "usetls");
    config_ptr->smtp_server_usetls = json_object_get_boolean(config_obj_ptr);

    config_obj_ptr = json_object_object_get(config_email_obj, "useauth");
    config_ptr->smtp_server_useauth = json_object_get_boolean(config_obj_ptr);

    config_obj_ptr = json_object_object_get(config_email_obj, "username");
    config_ptr->smtp_server_username = strdup(json_object_get_string(config_obj_ptr));

    config_obj_ptr = json_object_object_get(config_email_obj, "password");
    config_ptr->smtp_server_password = strdup(json_object_get_string(config_obj_ptr));
  }
  else
  {
    config_ptr->smtp_enabled = false;
  }

  json_object_put(config_obj);
  munmap(config_file_mmap, config_file_st.st_size);
  return true;
}