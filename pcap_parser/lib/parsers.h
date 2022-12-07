#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"
#include "flow_api.h"
#include <netinet/tcp.h>

struct parsed_payload {
  const u_char *data;
  uint data_len;
};

struct parsed_packet {

  // currently only used for IPv4
  struct in_addr src_ip;
  struct in_addr dst_ip;

  // protocol
  uint16_t protocol;

  union {
    struct tcphdr tcp;
    struct udphdr udp;
  };

  struct parsed_payload payload;
};

struct parsed_packet pkt_parser(const package packet, const package segment,
                                const package payload);

#endif
