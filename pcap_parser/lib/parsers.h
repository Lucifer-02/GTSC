#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"
#include "flow_api.h"

void ip_parser(const package packet, flow_base_t *flow);
void tcp_parser(const package segment, flow_base_t *flow);
void udp_parser(const package segment, flow_base_t *flow);
flow_base_t flow_parser(const package packet, const package segment,
                        const package payload);

#endif
