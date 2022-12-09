#include "dissection.h"

// Dessection of ethernet frame, return a frame
package frame_dissector(u_char const *packet,
                        struct pcap_pkthdr const *header) {

  /** // Show the size in bytes of the package */
  /** printf("Packet size: %d bytes\n", header->len); */

  // Show a warning if the length captured is different
  if (header->len != header->caplen) {
    printf("Warning! Capture size different than package size: %d bytes\n",
           header->len);
  }

  struct ether_header const *ethernet = (struct ether_header *)(packet);

  return (package){.header_pointer = (u_char *)ethernet,
                   .package_size = header->len,
                   .type = ethernet->ether_type,
                   .is_valid = true};
}

// Dessection of link layer, currently only IPv4, recieves ethernet frame and
// return packet
package link_dissector(package ethernet_packet) {

  if (ethernet_packet.type == IPv4) {
    u_char const *ip_pointer =
        ethernet_packet.header_pointer + ETHERNET_HEADER_SIZE;
    int ip_packet_size = ethernet_packet.package_size - ETHERNET_HEADER_SIZE;

    return (package){.header_pointer = ip_pointer,
                     .package_size = ip_packet_size,
                     .type = ((struct ip *)ip_pointer)->ip_p,
                     .is_valid = true};
  }

  printf("Not an IPv4\n");
  /** printf("-------------------------------------------------------------------" */
  /**        "----\n"); */

  return (package){.is_valid = false};
}

// Dessection of network layer, receive packet and return segment
package network_dissector(package packet) {

  struct ip const *ip = (struct ip *)packet.header_pointer;
  int ip_header_size = ip->ip_hl * 4;

  // check size of ip header
  if (ip_header_size < 20) {
    printf("   * Invalid IP header length: %u bytes\n", ip_header_size);
    goto END;
  }

  /** // print source and destination IP addresses  */
  /** printf("From: %s\n", inet_ntoa(ip->ip_src)); */
  /** printf("To: %s\n", inet_ntoa(ip->ip_dst)); */

  // check if TCP type
  if (ip->ip_p == IPPROTO_TCP) {

    /** printf("Protocol TCP\n"); */

    // get tcp header
    struct tcphdr const *tcp =
        (struct tcphdr *)(packet.header_pointer + ip_header_size);

    int segment_size = packet.package_size - ip_header_size;
    return (package){.header_pointer = (u_char *)tcp,
                     .package_size = segment_size,
                     .type = IPPROTO_TCP,
                     .is_valid = true};

  } else if (ip->ip_p == IPPROTO_UDP) {

    /** printf("Protocol UDP\n"); */

    // get udp header
    struct udphdr const *udp =
        (struct udphdr *)(packet.header_pointer + ip_header_size);

    int segment_size = packet.package_size - ip_header_size;

    return (package){
        .header_pointer = (u_char *)udp,
        .package_size = segment_size,
        .type = IPPROTO_UDP,
        .is_valid = true,
    };
  }

END:
  return (package){.is_valid = false};
}

// select the correct transport layer protocol
package transport_demux(package segment) {

  if (segment.type == IPPROTO_TCP) {
    return tcp_dissector(segment);
  } else if (segment.type == IPPROTO_UDP) {
    return udp_dissector(segment);
  }

  printf("Not TCP or UDP\n");

  return (package){.is_valid = false};
}

// Dessection of TCP segment, receive segment and return a payload
// NOTE: this function is only for transport_demux function
package tcp_dissector(package segment) {

  struct tcphdr const *tcp = (struct tcphdr *)segment.header_pointer;
  /** printf("Src port: %d\n", ntohs(tcp->th_sport)); */
  /** printf("Dst port: %d\n", ntohs(tcp->th_dport)); */

  /** // print sequence number and acknowledgement number and offset */
  /** printf("seq: %u, ack: %u, offset: %u \n", ntohl(tcp->th_seq), */
  /**        ntohl(tcp->th_ack), tcp->th_off); */

  int tcp_header_size = tcp->th_off * 4;
  // check size of tcp header
  if (tcp_header_size < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", tcp_header_size);

    return (package){.is_valid = false};
  }

  u_char const *payload = (u_char *)(segment.header_pointer + tcp_header_size);

  // get payload size
  int payload_size = segment.package_size - tcp_header_size;
  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

// Dessection of UDP segment, receive segment and return a payload
// NOTE: this function is only for transport_demux function
package udp_dissector(package segment) {

  /** const struct udphdr *udp = (struct udphdr *)segment.header_pointer; */

  /** // print source and destination port */
  /** printf("Src port: %d\n", ntohs(udp->uh_sport)); */
  /** printf("Dst port: %d\n", ntohs(udp->uh_dport)); */

  int udp_header_size = 8;

  // get payload
  u_char const *payload = (u_char *)(segment.header_pointer + udp_header_size);
  int payload_size = segment.package_size -
                     udp_header_size; // get payload size using udp header

  // print length of payload + checksum
  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

