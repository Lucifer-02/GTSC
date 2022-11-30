#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"
#include "flow_api.h"

struct parsed_packet {
  struct in_addr src_ip;
  struct in_addr dst_ip;
  in_port_t src_port;
  in_port_t dst_port;

  // type
  uint16_t type;

  // for tcp
  uint32_t seq;

  const u_char *payload;
  uint payload_len;
};

struct parsed_packet pkt_parser(const package packet, const package segment,
                                 const package payload);

#endif
