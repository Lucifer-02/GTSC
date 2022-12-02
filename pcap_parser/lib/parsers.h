#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"
#include "flow_api.h"

struct parsed_payload {
  const u_char *data;
  uint data_len;
};

struct parsed_packet {

  // currently only used for IPv4
  struct in_addr src_ip;
  struct in_addr dst_ip;
  in_port_t src_port;
  in_port_t dst_port;

  // type
  uint16_t type;

  // for tcp
  uint64_t seq;

  struct parsed_payload payload;
};

struct parsed_packet pkt_parser(const package packet, const package segment,
                                const package payload);

#endif
