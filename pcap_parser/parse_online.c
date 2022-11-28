#include "lib/dissection.h"
#include "lib/flow_api.h"
#include "lib/hash_table.h"

#define SNAP_LEN 1518

void get_packets(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet);
void ip_parser(const package packet, flow_base_t *flow);
void tcp_parser(const package segment, flow_base_t *flow);
void udp_parser(const package segment, flow_base_t *flow);
flow_base_t flow_parser(const package packet, const package segment,
                        const package payload);

int main() {

  char *dev = NULL;              /* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
  pcap_t *handle;                /* packet capture handle */

  char filter_exp[] = "ip";        /* filter expression [3] */
  struct bpf_program fp;           /* compiled filter program (expression) */
  bpf_u_int32 mask;                /* subnet mask */
  bpf_u_int32 net;                 /* ip */
  const int num_packets = 1000000; /* number of packets to capture */

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
                 const u_char *handle) {
  static int count = 1; /* packet counter */

  printf("\nPacket number %d:\n", count);
  count++;

  // Parse the packet
  //--------------------------------------------------------------------------
  const package frame = frame_dissect(handle, header);
  if (frame.is_valid == false) {
    goto END;
  }

  //--------------------------------------------------------------------------
  const package packet = link_dissect(frame);
  if (packet.is_valid == false) {
    goto END;
  }

  //--------------------------------------------------------------------------
  const package segment = network_dissect(packet);
  if (segment.is_valid == false) {
    goto END;
  }

  //--------------------------------------------------------------------------
  const package payload = transport_demux(segment);
  if (payload.is_valid == false) {
    goto END;
  }

  // insert to hash table
  const flow_base_t flow = flow_parser(packet, segment, payload);
  uint64_t id_key = flow.sip.s_addr + flow.dip.s_addr - flow.sp + flow.dp;

END:
  printf("-------------------------------------------------------------------"
         "----\n");
}

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

  // print IP addresses
  printf("Source IP: %s\n", inet_ntoa(flow.sip));
  printf("Destination IP: %s\n", inet_ntoa(flow.dip));

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
