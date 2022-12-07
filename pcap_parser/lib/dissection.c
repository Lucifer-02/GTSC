#include "dissection.h"
#include <sys/types.h>

// Dessection of ethernet frame, return a frame
package frame_dissector(const u_char *packet,
                        const struct pcap_pkthdr *header) {

  /** // Show the size in bytes of the package */
  /** printf("Packet size: %d bytes\n", header->len); */

  // Show a warning if the length captured is different
  if (header->len != header->caplen) {
    printf("Warning! Capture size different than package size: %d bytes\n",
           header->len);
  }

  const struct ether_header *ethernet = (struct ether_header *)(packet);

  return (package){.header_pointer = (u_char *)ethernet,
                   .package_size = header->len,
                   .type = ethernet->ether_type,
                   .is_valid = true};
}

// Dessection of link layer, currently only IPv4, recieves ethernet frame and
// return packet
package link_dissector(const package ethernet_packet) {

  if (ethernet_packet.type == IPv4) {
    const u_char *ip_pointer =
        ethernet_packet.header_pointer + ETHERNET_HEADER_SIZE;
    const int ip_packet_size =
        ethernet_packet.package_size - ETHERNET_HEADER_SIZE;

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
package network_dissector(const package packet) {

  const struct ip *ip = (struct ip *)packet.header_pointer;
  const int ip_header_size = ip->ip_hl * 4;

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
    const struct tcphdr *tcp =
        (struct tcphdr *)(packet.header_pointer + ip_header_size);

    const int segment_size = packet.package_size - ip_header_size;
    return (package){.header_pointer = (u_char *)tcp,
                     .package_size = segment_size,
                     .type = IPPROTO_TCP,
                     .is_valid = true};

  } else if (ip->ip_p == IPPROTO_UDP) {

    /** printf("Protocol UDP\n"); */

    // get udp header
    const struct udphdr *udp =
        (struct udphdr *)(packet.header_pointer + ip_header_size);

    const int segment_size = packet.package_size - ip_header_size;

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

// select the correct transport layer protocol, receive segment and return a
// payload
package transport_demux(const package segment) {

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
package tcp_dissector(const package segment) {

  const struct tcphdr *tcp = (struct tcphdr *)segment.header_pointer;
  /** printf("Src port: %d\n", ntohs(tcp->th_sport)); */
  /** printf("Dst port: %d\n", ntohs(tcp->th_dport)); */

  /** // print sequence number and acknowledgement number and offset */
  /** printf("seq: %u, ack: %u, offset: %u \n", ntohl(tcp->th_seq), */
  /**        ntohl(tcp->th_ack), tcp->th_off); */

  const int tcp_header_size = tcp->th_off * 4;
  // check size of tcp header
  if (tcp_header_size < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", tcp_header_size);

    return (package){.is_valid = false};
  }

  const u_char *payload = (u_char *)(segment.header_pointer + tcp_header_size);

  // get payload size
  const int payload_size = segment.package_size - tcp_header_size;
  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

// Dessection of UDP segment, receive segment and return a payload
// NOTE: this function is only for transport_demux function
package udp_dissector(const package segment) {

  /** const struct udphdr *udp = (struct udphdr *)segment.header_pointer; */

  /** // print source and destination port */
  /** printf("Src port: %d\n", ntohs(udp->uh_sport)); */
  /** printf("Dst port: %d\n", ntohs(udp->uh_dport)); */

  const int udp_header_size = 8;

  // get payload
  const u_char *payload = (u_char *)(segment.header_pointer + udp_header_size);
  const int payload_size = segment.package_size -
                           udp_header_size; // get payload size using udp header

  // print length of payload + checksum
  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

/*
 * print package payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, const uint payload_size) {

  /** if (payload_size > 0) { */
  /**   printf("\t\tpayload size: %u bytes\n", payload_size); */
  /** } else { */
  /**   printf("\t\tpayload size: 0 bytes\n"); */
  /**   return; */
  /** } */

  printf("\n");

  const int len = payload_size;
  int len_rem = payload_size;
  int line_width = 11; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char *ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for (;;) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

void print_hex_ascii_line(const u_char *const payload, int len, int offset) {

  int gap;
  const u_char *ch;

  /* offset */
  printf("\t\t%05d   ", offset);

  /* hex */
  ch = payload;
  for (int i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf(" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (int i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for (int i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}
