#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"
#include "flow_api.h"

struct parsed_packet {
  struct in_addr src_ip;
  struct in_addr dst_ip;
  in_port_t src_port;
  in_port_t dst_port;

  // for tcp
  uint32_t seq;

  char *payload;
  uint payload_len;
};

void ip_parser(const package packet, flow_base_t *flow);
void tcp_parser(const package segment, flow_base_t *flow);
void udp_parser(const package segment, flow_base_t *flow);
flow_base_t flow_parser(const package packet, const package segment,
                        const package payload);

#endif
