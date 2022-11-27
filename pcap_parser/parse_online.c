#include <ctype.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERNET_HEADER_SIZE 14
#define IPv4 0x0008
#define SNAP_LEN 1518

struct packet {
  const u_char *header_pointer;
  const int packet_size;
  const uint16_t type;
};

void get_packets(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet);
struct packet frame_parse(const u_char *packet,
                          const struct pcap_pkthdr *header);
struct packet link_parse(const struct packet frame_packet);
struct packet network_parse(const struct packet network_packet);
struct packet tcp_parse(const struct packet tcp_packet);
struct packet udp_parse(const struct packet udp_packet);
void print_payload(const struct packet payload_packet);
void print_hex_ascii_line(const u_char *const payload, int len, int offset);

int main() {

  char *dev = NULL;              /* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
  pcap_t *handle;                /* packet capture handle */

  char filter_exp[] = "ip"; /* filter expression [3] */
  struct bpf_program fp;    /* compiled filter program (expression) */
  bpf_u_int32 mask;         /* subnet mask */
  bpf_u_int32 net;          /* ip */
  const int num_packets = 1000000;     /* number of packets to capture */

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  // get network number and mask associated with capture device
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  // print capture info
  printf("Device: %s\n", dev);
  printf("Number of packets: %d\n", num_packets);
  printf("Filter expression: %s\n", filter_exp);

  // open capture device
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  // make sure we're capturing on an Ethernet device [2]
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }

  // compile the filter expression
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  // apply the compiled filter
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  // now we can set our callback function
  pcap_loop(handle, num_packets, get_packets, NULL);

  return 0;
}

void get_packets(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet) {
  static int count = 1; /* packet counter */

  printf("\nPacket number %d:\n", count);
  count++;

  // Parse the packet
  const struct packet ethernet_packet = frame_parse(packet, header);
  const struct packet ip_packet = link_parse(ethernet_packet);
  const struct packet transport_packet = network_parse(ip_packet);
  print_payload(transport_packet);
}

// Dessection of ethernet frame
struct packet frame_parse(const u_char *packet,
                          const struct pcap_pkthdr *header) {
  // Show the size in bytes of the packet
  printf("Packet size: %d bytes\n", header->len);

  // Show a warning if the length captured is different
  if (header->len != header->caplen) {
    printf("Warning! Capture size different than packet size: %d bytes\n",
           header->len);
  }

  const struct ether_header *ethernet = (struct ether_header *)(packet);

  return (struct packet){.header_pointer = (u_char *)ethernet,
                         .packet_size = header->len,
                         .type = ethernet->ether_type};
}

// Dessection of link layer packet
struct packet link_parse(const struct packet ethernet_packet) {

  if (ethernet_packet.type == IPv4) {
    const u_char *ip_pointer =
        ethernet_packet.header_pointer + ETHERNET_HEADER_SIZE;
    const int ip_packet_size =
        ethernet_packet.packet_size - ETHERNET_HEADER_SIZE;

    return (struct packet){
        .header_pointer = ip_pointer,
        .packet_size = ip_packet_size,
        .type = ((struct ip *)ip_pointer)->ip_p,
    };
  }

  printf("Not an IPv4\n");
  printf("-------------------------------------------------------------------"
         "----\n");
  return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
}

// Dessection of network layer packet
struct packet network_parse(const struct packet network_packet) {

  // check null
  if (network_packet.header_pointer == NULL) {
    return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
  }

  const struct tcphdr *tcp; /* The TCP header */
  const struct udphdr *udp; /* The UDP header */

  const struct ip *ip = (struct ip *)network_packet.header_pointer;
  const int ip_header_size = ip->ip_hl * 4;

  // check size of ip header
  if (ip_header_size < 20) {
    printf("   * Invalid IP header length: %u bytes\n", ip_header_size);
    return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
  }

  /* print source and destination IP addresses */
  printf("From: %s\n", inet_ntoa(ip->ip_src));
  printf("To: %s\n", inet_ntoa(ip->ip_dst));

  // check if TCP type
  if (ip->ip_p == IPPROTO_TCP) {
    printf("Protocol TCP\n");
    tcp = (struct tcphdr *)(network_packet.header_pointer + ip_header_size);

    const int tcp_packet_size = network_packet.packet_size - ip_header_size;
    return tcp_parse((struct packet){.header_pointer = (u_char *)tcp,
                                     .packet_size = tcp_packet_size,
                                     .type = 0});

  } else if (ip->ip_p == IPPROTO_UDP) {
    printf("Protocol UDP\n");
    udp = (struct udphdr *)(network_packet.header_pointer + ip_header_size);

    const int udp_packet_size = network_packet.packet_size - ip_header_size;
    return udp_parse((struct packet){.header_pointer = (u_char *)udp,
                                     .packet_size = udp_packet_size,
                                     .type = 0});

  } else {
    printf("Not TCP or UDP\n");
  }
  printf("-------------------------------------------------------------------"
         "----\n");

  return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
}

// Dessection of tcp packet
struct packet tcp_parse(const struct packet tcp_packet) {

  // check null
  if (tcp_packet.header_pointer == NULL) {
    return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
  }

  const struct tcphdr *tcp = (struct tcphdr *)tcp_packet.header_pointer;
  printf("Src port: %d\n", ntohs(tcp->th_sport));
  printf("Dst port: %d\n", ntohs(tcp->th_dport));

  // print sequence number and acknowledgement number and offset
  printf("seq: %u, ack: %u, offset: %u \n", ntohl(tcp->th_seq),
         ntohl(tcp->th_ack), tcp->th_off);

  const int size_tcp = tcp->th_off * 4;
  const u_char *payload;
  payload = (u_char *)(tcp_packet.header_pointer + size_tcp);

  // get payload size
  const int payload_size = tcp_packet.packet_size - size_tcp;
  return (struct packet){
      .header_pointer = payload, .packet_size = payload_size, .type = 0};
}

// Dessection of udp packet
struct packet udp_parse(const struct packet udp_packet) {

  // check null
  if (udp_packet.header_pointer == NULL) {
    return (struct packet){.header_pointer = NULL, .packet_size = 0, .type = 0};
  }

  const struct udphdr *udp = (struct udphdr *)udp_packet.header_pointer;
  // print source and destination port
  printf("Src port: %d\n", ntohs(udp->uh_sport));
  printf("Dst port: %d\n", ntohs(udp->uh_dport));

  const int size_udp = 8;
  const u_char *payload;

  // get payload
  payload = (u_char *)(udp_packet.header_pointer + size_udp);
  const int payload_size =
      udp_packet.packet_size - size_udp; // get payload size using udp header

  // print length of payload + checksum
  return (struct packet){
      .header_pointer = payload, .packet_size = payload_size, .type = 0};
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const struct packet payload_packet) {

  // check if payload is null
  if (payload_packet.header_pointer == NULL) {
    return;
  }

  if (payload_packet.packet_size > 0) {
    printf("payload size: %d bytes\n", payload_packet.packet_size);
  }

  printf("-------------------------------------------------------------------"
         "----\n");
  const int len = payload_packet.packet_size;
  int len_rem = payload_packet.packet_size;
  int line_width = 11; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char *ch = payload_packet.header_pointer;

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
  printf("%05d   ", offset);

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
