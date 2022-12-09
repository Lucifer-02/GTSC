#ifndef DISSECTION_H
#define DISSECTION_H

#include <ctype.h>
#include <pcap.h>
#include <stdbool.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERNET_HEADER_SIZE 14
#define IPv4 0x0008
#define NONE 0x0000

typedef struct {
  u_char const *header_pointer;
  uint package_size;
  uint16_t type;
  bool is_valid;
} package;

package frame_dissector(u_char const *packet, struct pcap_pkthdr const *header);
package link_dissector(package frame);
package network_dissector(package packet);

// select the correct transport layer protocol
package transport_demux(package segment);
package tcp_dissector(package segment);
package udp_dissector(package segment);


#endif
