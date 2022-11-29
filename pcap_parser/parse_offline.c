#include "lib/dissection.h"
#include "lib/flow_api.h"
#include "lib/hash_table.h"

#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

const int HASH_TABLE_SIZE = 50000;

void get_packets(pcap_t *handler);
void ip_parser(const package packet, flow_base_t *flow);
void tcp_parser(const package segment, flow_base_t *flow);
void udp_parser(const package segment, flow_base_t *flow);
flow_base_t flow_parser(const package packet, const package segment,
                        const package payload);
int count_nodes(const HashTable table);

int main() {

  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline("sample.pcap", errbuff);
  get_packets(handler);
  pcap_close(handler);
  return 0;
}

void get_packets(pcap_t *handler) {

  // The header that pcap gives us
  struct pcap_pkthdr *header;

  // The actual packet
  const u_char *packet;

  int packetCount = 0;

  // create hash table
  HashTable table = newHashTable(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    // Show the packet number
    printf("Packet # %i\n", ++packetCount);

    //--------------------------------------------------------------------------
    const package frame = frame_dissect(packet, header);
    if (frame.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    const package packet = link_dissect(frame);
    if (packet.is_valid== false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    const package segment = network_dissect(packet);
    if (segment.is_valid== false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    const package payload = transport_demux(segment);
    if (payload.is_valid== false) {
      goto END;
    }

    // insert to hash table
    const flow_base_t flow = flow_parser(packet, segment, payload);
    uint64_t id_key = flow.sip.s_addr + flow.dip.s_addr - flow.sp + flow.dp;
    insert(table, id_key, flow);

  END:
    printf("-------------------------------------------------------------------"
           "----\n");
  }
  // print table
  print_hashtable(table);
  printf("table size: %d\n", count_nodes(table));
}

