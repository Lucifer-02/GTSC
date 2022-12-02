#include "parsers.h"

struct parsed_packet pkt_parser(const package packet, const package segment,
                                const package payload) {

  struct parsed_packet pkt;

  const struct ip *ip_header = (struct ip *)packet.header_pointer;

  pkt.src_ip = ip_header->ip_src;
  pkt.dst_ip = ip_header->ip_dst;

  // print IP addresses
  printf("Source IP: %s\n", inet_ntoa(pkt.src_ip));
  printf("Destination IP: %s\n", inet_ntoa(pkt.dst_ip));

  if (segment.type == IPPROTO_TCP) {
    const struct tcphdr *tcp_header = (struct tcphdr *)segment.header_pointer;

    pkt.type = IPPROTO_TCP;
    pkt.src_port = ntohs(tcp_header->source);
    pkt.dst_port = ntohs(tcp_header->dest);
    pkt.seq = ntohl(tcp_header->seq);
    pkt.payload.data = payload.header_pointer;
    pkt.payload.data_len = payload.package_size;

	printf("Protocol: TCP\n");
    printf("Source port: %d\n", pkt.src_port);
    printf("Destination port: %d\n", pkt.dst_port);
    printf("Sequence number: %ld\n", pkt.seq);
    printf("Payload size: %d\n", pkt.payload.data_len);

  } else if (segment.type == IPPROTO_UDP) {

    const struct udphdr *udp_header = (struct udphdr *)segment.header_pointer;

    pkt.type = IPPROTO_UDP;
    pkt.src_port = ntohs(udp_header->source);
    pkt.dst_port = ntohs(udp_header->dest);
    pkt.payload.data = payload.header_pointer;
    pkt.payload.data_len = payload.package_size;
    pkt.seq = NONE;

	printf("Protocol: UDP\n");
    printf("Source port: %d\n", pkt.src_port);
    printf("Destination port: %d\n", pkt.dst_port);
    printf("Payload size: %d\n", pkt.payload.data_len);
  }

  return pkt;
}
