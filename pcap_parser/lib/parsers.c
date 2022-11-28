#include "parsers.h"

void ip_parser(const package packet, flow_base_t *flow) {

  const struct ip *ip_header = (struct ip *)packet.header_pointer;

  (*flow).sip = ip_header->ip_src;
  (*flow).dip = ip_header->ip_dst;
}

void tcp_parser(const package segment, flow_base_t *flow) {

  const struct tcphdr *tcp_header = (struct tcphdr *)segment.header_pointer;

  (*flow).sp = ntohs(tcp_header->source);
  (*flow).dp = ntohs(tcp_header->dest);
}

void udp_parser(const package segment, flow_base_t *flow) {

  const struct udphdr *udp_header = (struct udphdr *)segment.header_pointer;

  (*flow).sp = ntohs(udp_header->source);
  (*flow).dp = ntohs(udp_header->dest);
}

flow_base_t flow_parser(const package packet, const package segment,
                        const package payload) {

  flow_base_t flow;
  ip_parser(packet, &flow);

  /** // print IP addresses */
  /** printf("Source IP: %s\n", inet_ntoa(flow.sip)); */
  /** printf("Destination IP: %s\n", inet_ntoa(flow.dip)); */

  if (segment.type == IPPROTO_TCP) {
    tcp_parser(segment, &flow);
    /** printf("Source port: %d\n", flow.sp); */
    /** printf("Destination port: %d\n", flow.dp); */

  } else if (segment.type == IPPROTO_UDP) {
    udp_parser(segment, &flow);
    /** printf("Source port: %d\n", flow.sp); */
    /** printf("Destination port: %d\n", flow.dp); */
  }

  return flow;
}
