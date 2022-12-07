#ifndef DISSECTION_H
#define DISSECTION_H

#include <ctype.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERNET_HEADER_SIZE 14
#define IPv4 0x0008
#define NONE 0x0000

typedef struct {
  const u_char *header_pointer;
  uint package_size;
  uint16_t type;
  bool is_valid;
} package;

package frame_dissector(const u_char *packet, const struct pcap_pkthdr *header);
package link_dissector(const package frame);
package network_dissector(const package packet);
package transport_demux(const package segment);
package tcp_dissector(const package segment);
package udp_dissector(const package segment);
void print_payload(const u_char *payload, const uint payload_size);
void print_hex_ascii_line(const u_char *const payload, int len, int offset);

#endif
