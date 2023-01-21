#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main.h"
#include "sniff.h"
#include "email.h"
#include "ouilist.h"
#include "util/timing.h"

#define CONFIG_FILENAME "config.json"

static app_data_t app_data = {
  .exit_requested = false,

  .interface_v4_addresses = NULL,
  .interface_v4_addresses_count = 0,
  .interface_v6_addresses = NULL,
  .interface_v6_addresses_count = 0,

  .interface_addresses_string = NULL,

  .ouilist = {
    .loaded = false
  },

  .incident = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .active = false
  }
};

static pthread_t notification_pthread;

static pcap_t *capture_pcap_ptr = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];

static void _print_usage(void)
{
  printf(
    "\n"
    "Usage: tripwire [options]\n"
    "\n"
    "  -c, --config <filename>  Set the configuration file (default: ./config.json)\n"
    "\n"
  );
}

static void _print_interfaces(void)
{
  pcap_if_t *it = NULL;
  char buf4[INET_ADDRSTRLEN];
  char buf6[INET6_ADDRSTRLEN];

  if(pcap_findalldevs(&it, errbuf) == 0)
  {
    printf("Available interfaces:\n");
    bool is_addressed;
    while (it)
    {
      is_addressed = false;
      for(pcap_addr_t *a=it->addresses; a!=NULL; a=a->next)
      {
        if(a->addr->sa_family == AF_INET)
        {
          if(!is_addressed)
          {
            printf(" %s", it->name);
            is_addressed = true;
          }
          inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, buf4, sizeof(buf4));
          printf(" [%s]", buf4);
        }
        else if(a->addr->sa_family == AF_INET6)
        {
          if(!is_addressed)
          {
            printf(" %s", it->name);
            is_addressed = true;
          }
          inet_ntop(AF_INET6, &((struct sockaddr_in6*)a->addr)->sin6_addr, buf6, sizeof(buf6));
          printf(" [%s]", buf6);
        }
      }
      if(is_addressed)
      {
        printf("\n");
      }

      it = it->next;
    }
    printf("\n");
    pcap_freealldevs(it);
  }
  else
  {
    fprintf(stderr, "error retrieving interfaces: %s\n", errbuf);
  }
  printf("\n");
}

void sigint_handler(int sig)
{
    (void)sig;
    app_data.exit_requested = true;
    if(capture_pcap_ptr != NULL)
    {
      pcap_breakloop(capture_pcap_ptr);
    }
}

static inline char *generate_ports_filter_string(config_t *config_ptr)
{
  int32_t ports_count = 0;
  char *filter_string = NULL;
  char *filter_init;

  while(config_ptr->listen_ports[ports_count] != 0)
  {
    ports_count++;
  }

  if(ports_count == 0)
  {
    return NULL;
  }
  else if(ports_count == 1)
  {
    filter_init = (config_ptr->listen_icmp ? "icmp or port" : "port");

    /* Single port */
    if(asprintf(&filter_string, "%s %d", filter_init, config_ptr->listen_ports[0]) < 0)
    {
      return NULL;
    }
  }
  else
  {
    /* Multiple ports */
    /* example output: "port (80 or 443)" */

    uint32_t filter_string_length;

    filter_init = (config_ptr->listen_icmp ? "icmp or port (" : "port (");

    filter_string_length = strlen(filter_init);

    filter_string = malloc(filter_string_length);

    memcpy(filter_string, filter_init, strlen(filter_init));

    char *port_string;
    for(int32_t port_index = 0; port_index < ports_count; port_index++)
    {
      if(asprintf(&port_string, "%d", config_ptr->listen_ports[port_index]) < 0)
      {
        free(filter_string);
        return NULL;
      }

      /* Allocate space for new port */
      filter_string = realloc(filter_string, filter_string_length + strlen(port_string) + 4 + 1);

      sprintf(&filter_string[filter_string_length], "%s or ", port_string);
      filter_string_length += strlen(port_string) + 4;

      free(port_string);
    }

    sprintf(&filter_string[filter_string_length-4], ")");
    filter_string[filter_string_length-3] = '\0';
    filter_string[filter_string_length-2] = '\0';
    filter_string[filter_string_length-1] = '\0';
  }

  return filter_string;
}

static inline void sprint_macaddr_hex(char *buffer, const u_char *macaddr)
{
  sprintf(buffer,
    "%02x:%02x:%02x:%02x:%02x:%02x",
    macaddr[0],
    macaddr[1],
    macaddr[2],
    macaddr[3],
    macaddr[4],
    macaddr[5]
  );
}

static void find_interface_addresses(app_data_t *app_data_ptr, char *interface_name)
{
  pcap_if_t *it = NULL;

  if(pcap_findalldevs(&it, errbuf) == 0)
  {
    while (it)
    {
      if(0 != strcmp(it->name, interface_name))
      {
        it = it->next;
        continue;
      }

      for(pcap_addr_t *a=it->addresses; a!=NULL; a=a->next)
      {
        if(a->addr->sa_family == AF_INET)
        {
          if(app_data_ptr->interface_v4_addresses == NULL)
          {
            app_data_ptr->interface_v4_addresses = malloc(sizeof(struct in_addr));
          }
          else
          {
            app_data_ptr->interface_v4_addresses = realloc(app_data_ptr->interface_v4_addresses, (app_data_ptr->interface_v4_addresses_count + 1) * sizeof(struct in_addr));
          }

          memcpy(
            &app_data_ptr->interface_v4_addresses[app_data_ptr->interface_v4_addresses_count],
            &((struct sockaddr_in*)a->addr)->sin_addr,
            sizeof(struct in_addr)
          );

          app_data_ptr->interface_v4_addresses_count += 1;
        }
        else if(a->addr->sa_family == AF_INET6)
        {
          if(app_data_ptr->interface_v6_addresses == NULL)
          {
            app_data_ptr->interface_v6_addresses = malloc(sizeof(struct in6_addr));
          }
          else
          {
            app_data_ptr->interface_v6_addresses = realloc(app_data_ptr->interface_v6_addresses, (app_data_ptr->interface_v6_addresses_count + 1) * sizeof(struct in6_addr));
          }

          memcpy(
            &app_data_ptr->interface_v6_addresses[app_data_ptr->interface_v6_addresses_count],
            &((struct sockaddr_in6*)a->addr)->sin6_addr,
            sizeof(struct in6_addr)
          );

          app_data_ptr->interface_v6_addresses_count += 1;
        }
      }
      break;
    }
    pcap_freealldevs(it);

    /* Produce string output */
    app_data_ptr->interface_addresses_string = strdup("");
    int32_t output_buffer_length = 0;

    if(app_data_ptr->interface_v4_addresses_count > 0 || app_data_ptr->interface_v6_addresses_count > 0)
    {
      char address4_buffer[INET_ADDRSTRLEN];

      for(int32_t i = 0; i < app_data_ptr->interface_v4_addresses_count; i++)
      {
        inet_ntop(AF_INET, &app_data_ptr->interface_v4_addresses[i], address4_buffer, sizeof(address4_buffer));

        /* Allocate space for new port */
        app_data_ptr->interface_addresses_string = realloc(app_data_ptr->interface_addresses_string, output_buffer_length + strlen(address4_buffer) + 3 + 1);

        sprintf(&app_data_ptr->interface_addresses_string[output_buffer_length], " [%s]", address4_buffer);
        output_buffer_length += strlen(address4_buffer) + 3;
      }

      char address6_buffer[INET6_ADDRSTRLEN];

      for(int32_t i = 0; i < app_data_ptr->interface_v6_addresses_count; i++)
      {
        inet_ntop(AF_INET6, &app_data_ptr->interface_v6_addresses[i], address6_buffer, sizeof(address6_buffer));

        /* Allocate space for new port */
        app_data_ptr->interface_addresses_string = realloc(app_data_ptr->interface_addresses_string, output_buffer_length + strlen(address6_buffer) + 3 + 1);

        sprintf(&app_data_ptr->interface_addresses_string[output_buffer_length], " [%s]", address6_buffer);
        output_buffer_length += strlen(address6_buffer) + 3;
      }
    }
  }
  else
  {
    printf("error retrieving interfaces: %s\n", errbuf);
  }
}

static void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  (void)args;
  (void)header;

  /* Pointers to header structs */
  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;
  struct sniff_tcp *tcp;
  struct sniff_udp *udp;

  int size_ip;
  int size_tcp;

  ethernet = (struct sniff_ethernet*)(packet);

  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if(size_ip < 20)
  {
    /* Invalid IP header length */
    return;
  }

  if(app_data.config.listen_ignore_local_source)
  {
    for(int32_t i = 0; i < app_data.interface_v4_addresses_count; i++)
    {
      if(0 == memcmp(&ip->ip_src, &(app_data.interface_v4_addresses[i]), sizeof(struct in_addr)))
      {
        return;
      }
    }
    /* IPv6 not yet supported */
  }

  incident_entry_t *incident_entry_ptr;

  if(app_data.incident.active == false)
  {
    printf("New incident triggered.\n");
  }

  /* Lock to avoid clashing with notification thread */
  pthread_mutex_lock(&app_data.incident.lock);

  if(app_data.incident.active == true)
  {
    /* Incident already running, add to incident array */
    app_data.incident.entries_count++;
    app_data.incident.entries = realloc(app_data.incident.entries, app_data.incident.entries_count * sizeof(incident_entry_t));
  }
  else
  {
    /* Start new incident */
    app_data.incident.active = true;
    app_data.incident.starttime_ms = timestamp_ms();
    /* Allocate slot for first incident */
    app_data.incident.entries_count = 1;
    app_data.incident.entries = malloc(1 * sizeof(incident_entry_t));
  }

  incident_entry_ptr = &(app_data.incident.entries[app_data.incident.entries_count - 1]);

  incident_entry_ptr->timestamp_ms = timestamp_ms();
  memcpy(&(incident_entry_ptr->src_addr), &(ip->ip_src), sizeof(struct in_addr));
  memcpy(&(incident_entry_ptr->src_mac), &(ethernet->ether_shost), sizeof(u_char) * ETHER_ADDR_LEN);
  incident_entry_ptr->ip_proto = ip->ip_p;

  if(ip->ip_p == IPPROTO_TCP)
  {
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    /* Validate TCP Header Length */
    if(size_tcp >= 20)
    {
      incident_entry_ptr->src_port = ntohs(tcp->th_sport);
      incident_entry_ptr->dst_port = ntohs(tcp->th_dport);
      incident_entry_ptr->tcp_th_flags = tcp->th_flags;
    }
  }
  else if(ip->ip_p == IPPROTO_UDP)
  {
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
    incident_entry_ptr->src_port = ntohs(udp->uh_sport);
    incident_entry_ptr->dst_port = ntohs(udp->uh_dport);
  }

  pthread_mutex_unlock(&app_data.incident.lock);
}

static void *notification_thread(void *arg)
{
  app_data_t *app_data_ptr = (app_data_t*)arg;

  incident_t incident_cache;

  while(!app_data_ptr->exit_requested)
  {
    /* Lock to avoid clashing with packet thread */
    pthread_mutex_lock(&app_data_ptr->incident.lock);

    if(app_data_ptr->incident.active && (app_data_ptr->incident.starttime_ms + (1000 * app_data.config.notification_latency_s)) < timestamp_ms())
    {
      /* Make local copy. Warning: Allocated entries buffer is copied over and is ours now! */
      memcpy(&incident_cache, &app_data_ptr->incident, sizeof(incident_t));

      /* Clear incident object*/
      app_data_ptr->incident.active = false;

      pthread_mutex_unlock(&app_data_ptr->incident.lock);

      /* Construct notification from local copy of incident */

      char *email_body = NULL;
      int32_t email_body_length = 0;
      char *email_line = NULL;
      int32_t email_line_length = 0;

      incident_entry_t *incident_cache_entry_ptr;

      time_t entry_time;
      char entry_time_string[32];
      char ipaddr_string[INET_ADDRSTRLEN];
      char macaddr_string[32];
      char oui_string[128];

      email_body_length = asprintf(
        &email_body,
        "The following traffic was detected by Tiny Tripwire:\n\n"
      );

      for(int32_t entry_index = 0; entry_index < incident_cache.entries_count; entry_index++)
      {
        incident_cache_entry_ptr = &(incident_cache.entries[entry_index]);

        entry_time = (time_t)(incident_cache_entry_ptr->timestamp_ms / 1000);
        strftime(entry_time_string, 31, "%Y-%m-%d %H:%M:%S", gmtime(&entry_time));

        inet_ntop(AF_INET, &(incident_cache_entry_ptr->src_addr), ipaddr_string, INET_ADDRSTRLEN);

        sprint_macaddr_hex(macaddr_string, incident_cache_entry_ptr->src_mac);

        oui_string[0] = '\0';
        oui_lookup(&(app_data_ptr->ouilist), macaddr_string, oui_string, sizeof(oui_string));

        if(incident_cache_entry_ptr->ip_proto == IPPROTO_TCP)
        {
          email_line_length = asprintf(&email_line, "* [%s] TCP ports: %u -> %u [%s%s%s%s], %s <%s> (%s)\n",
            entry_time_string,
            incident_cache_entry_ptr->src_port,
            incident_cache_entry_ptr->dst_port,
            (incident_cache_entry_ptr->tcp_th_flags & TH_SYN) ? "S" : "",
            (incident_cache_entry_ptr->tcp_th_flags & TH_ACK) ? "A" : "",
            (incident_cache_entry_ptr->tcp_th_flags & TH_FIN) ? "F" : "",
            (incident_cache_entry_ptr->tcp_th_flags & TH_RST) ? "R" : "",
            ipaddr_string,
            macaddr_string,
            oui_string
          );
        }
        else if(incident_cache_entry_ptr->ip_proto == IPPROTO_UDP)
        {
          email_line_length = asprintf(&email_line, "* [%s] UDP ports: %u -> %u, %s <%s> (%s)\n",
            entry_time_string,
            incident_cache_entry_ptr->src_port,
            incident_cache_entry_ptr->dst_port,
            ipaddr_string,
            macaddr_string,
            oui_string
          );
        }
        else if(incident_cache_entry_ptr->ip_proto == IPPROTO_ICMP)
        {
          email_line_length = asprintf(&email_line, "* [%s] ICMP, %s <%s> (%s)\n",
            entry_time_string,
            ipaddr_string,
            macaddr_string,
            oui_string
          );
        }
        else
        {
          email_line_length = asprintf(&email_line, "* [%s] ???, %s <%s> (%s)\n",
            entry_time_string,
            ipaddr_string,
            macaddr_string,
            oui_string
          );
        }

        if(email_line_length > 0)
        {
          email_body = realloc(email_body, email_body_length + email_line_length);

          memcpy(&email_body[email_body_length], email_line, email_line_length);
          email_body_length += email_line_length;

          free(email_line);
          email_line = NULL;
        }
      }

      /* Add footer */
      email_line_length = asprintf(&email_line,
        "\n"
        "(Timestamps are in UTC, local addresses on this host: %s)\n",
        app_data_ptr->interface_addresses_string
      );
      email_body = realloc(email_body, email_body_length + email_line_length);
      memcpy(&email_body[email_body_length], email_line, email_line_length);
      email_body_length += email_line_length;
      free(email_line);

      /* Ensure null-termination */
      email_body = realloc(email_body, email_body_length + 1);
      email_body[email_body_length] = '\0';
      email_body_length++;

      email_t email_notification = {
        .to = app_data.config.notification_email_destination,
        .from = app_data.config.notification_email_source,
        .subject = app_data.config.notification_email_subject,
        .message = email_body
      };

      printf("Sending Notification Email, %d incident entries.\n", incident_cache.entries_count);

      email(&(app_data.config), &email_notification);

      if(email_body != NULL)
      {
        free(email_body);
      }
      if(email_line != NULL)
      {
        free(email_line);
      }
      free(incident_cache.entries);
    }
    else
    {
      pthread_mutex_unlock(&app_data_ptr->incident.lock);
    }

    sleep_ms(500);
  }

  pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
  int opt, c;

  char *config_filename = NULL;

  char *ports_filter_string;
  bpf_u_int32 ipaddr;
  bpf_u_int32 ipmask;
  struct bpf_program capture_filter;

  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigint_handler);

  printf("Tiny Tripwire\n");
  fflush(stdout);

  static const struct option long_options[] = {
    { "config",  optional_argument, 0, 'c' },
    { 0,         0,                 0,  0  }
  };
  
  while((c = getopt_long(argc, argv, "c:", long_options, &opt)) != -1)
  {
    switch(c)
    {
      case 'c': /* --config <filename> */
        config_filename = optarg;
        break;
      
      case '?':
        _print_usage();
        _print_interfaces();
        return 0;
    }
  }

  if(config_filename == NULL)
  {
    config_filename = strdup(CONFIG_FILENAME);
  }

  if(!load_config(config_filename, &app_data.config))
  {
    fprintf(stderr, "Failed to load config file \"%s\"\n", config_filename);
    return -1;
  }
  printf(" - loaded config file: %s\n", config_filename);
  fflush(stdout);


  if(app_data.config.notification_ouilist_filename != NULL && strlen(app_data.config.notification_ouilist_filename) > 0)
  {
    if(oui_loadfile(&(app_data.ouilist), app_data.config.notification_ouilist_filename))
    {
      printf(" - successfully loaded %d entries in OUI list.\n", app_data.ouilist.entries_count);
    }
    else
    {
      fprintf(stderr, " - warning: failed to load OUI list from \"%s\"\n", app_data.config.notification_ouilist_filename);
    }
  }
  fflush(stdout);

  ports_filter_string = generate_ports_filter_string(&app_data.config);
  if(ports_filter_string == NULL)
  {
    fprintf(stderr, "Error parsing port filter string\n");
    _print_usage();
    _print_interfaces();
    return -1;
  }

  if(pcap_lookupnet(app_data.config.listen_interface, &ipaddr, &ipmask, errbuf) == -1)
  {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", app_data.config.listen_interface, errbuf);
    ipaddr = 0x00000000;
    ipmask = 0x00000000;
  }

  capture_pcap_ptr = pcap_open_live(app_data.config.listen_interface, SNAP_LEN, 1, 1000, errbuf);
  if(capture_pcap_ptr == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", app_data.config.listen_interface, errbuf);
    _print_interfaces();
    return -1;
  }
  if(pcap_datalink(capture_pcap_ptr) != DLT_EN10MB)
  {
    fprintf(stderr, "%s is not an Ethernet Interface\n", app_data.config.listen_interface);
    return -1;
  }
  find_interface_addresses(&app_data, app_data.config.listen_interface);
  printf(" - successfully opened interface: %s %s\n", app_data.config.listen_interface, app_data.interface_addresses_string);
  fflush(stdout);

  if(pcap_compile(capture_pcap_ptr, &capture_filter, ports_filter_string, true, ipmask) == -1)
  {
    fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(capture_pcap_ptr));
    return -1;
  }
  printf(" - successfully parsed filter.\n");
  fflush(stdout);

  if(pcap_setfilter(capture_pcap_ptr, &capture_filter) < 0)
  {
    fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(capture_pcap_ptr));
    return -1;
  }
  printf(" - successfully installed filter.\n");
  fflush(stdout);

  pthread_create(&notification_pthread, NULL, notification_thread, (void *)(&app_data));


  printf("Running capture..\n");
  fflush(stdout);

  /* Blocking loop */
  pcap_loop(capture_pcap_ptr, 0, process_packet, NULL);

  fprintf(stderr, "Capture aborted. Closing application..\n");

  pcap_freecode(&capture_filter);
  pcap_close(capture_pcap_ptr);

  free(ports_filter_string);
  free(config_filename);

  return 0;
}