#include "lib/dissection.h"
#include "lib/flow_api.h"
#include "lib/hash_table.h"

#define SNAP_LEN 1518
const int HASH_TABLE_SIZE = 50;

void get_packets(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet);
int main() {
  // live ip capture
  char *dev = "enp0s31f6";
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *handler;
  struct bpf_program fp;
  char filter_exp[] = "ip";
  bpf_u_int32 mask;
  bpf_u_int32 net;
  int num_packets = 100;

  // find the properties for the device
  if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s", dev, errbuff);
    net = 0;
    mask = 0;
  }

  // open device for live capture
  handler = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuff);
  if (handler == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s", dev, errbuff);
    exit(EXIT_FAILURE);
  }

  // compile the filter expression
  if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s", filter_exp,
            pcap_geterr(handler));
    exit(EXIT_FAILURE);
  }

  // apply the compiled filter
  if (pcap_setfilter(handler, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s", filter_exp,
            pcap_geterr(handler));
    exit(EXIT_FAILURE);
  }

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  // capture packets
  pcap_loop(handler, num_packets, get_packets, (u_char *)&table);

  // cleanup
  pcap_freecode(&fp);
  pcap_close(handler);

  print_hashtable(table);
  free_hash_table(table);

  return 0;
}

void get_packets(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *handle) {

  static int count = 1; /* packet counter */

  printf("\nPacket number %d:\n", count);
  count++;

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
  struct parsed_packet pkt = pkt_parser(packet, segment, payload);
  insert_packet(*(HashTable *)args, pkt);

END:
  printf("-------------------------------------------------------------------"
         "----\n");
}
