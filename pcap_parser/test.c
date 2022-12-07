#include "lib/dissection.h"
#include "lib/flow_api.h"
#include "lib/hash_table.h"
#include "lib/linked_list.h"
#include "lib/parsers.h"
#include <netinet/tcp.h>
#include <stdio.h>

const int HASH_TABLE_SIZE = 50;

void get_packets(pcap_t *handler);
// handle to skip tcp handshake packets
void skip_handshake(HashTable table, struct parsed_packet pkt);

int main() {

  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline("sample.pcap", errbuff);
  if (handler == NULL) {
    fprintf(stderr, "Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }
  get_packets(handler);
  pcap_close(handler);
  return 0;
}

void get_packets(pcap_t *handler) {

  // The header that pcap gives us
  struct pcap_pkthdr *header;

  // The actual packet
  const u_char *full_packet;

  int packetCount = 0;

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header, &full_packet) >= 0) {

    // Show the packet number
    printf("Packet # %i\n", ++packetCount);

    //--------------------------------------------------------------------------
    const package frame = frame_dissector(full_packet, header);
    if (frame.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    const package packet = link_dissector(frame);
    if (packet.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    const package segment = network_dissector(packet);
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
	/** insert_packet(table, pkt); */
	skip_handshake(table, pkt);

  END:
    printf("-------------------------------------------------------------------"
           "----\n");
  }

  /** printf( */
  /**     "data length: %d\n", */
  /**     pop_head_payload(&search_flow(table,
   * 2961644043)->package_up).data_len); */
  /** printf( */
  /**     "data length: %d\n", */
  /**     pop_head_payload(&search_flow(table,
   * 2961644043)->package_up).data_len); */
  /** print_hashtable(table); */
  /** printf("number of flows: %d\n", count_flows(table)); */
  /** printf("Number of packets: %d\n", count_packets(table)); */

  print_flow(*search_flow(table, 2961644043));

  free_hash_table(table);
}

// handle to skip tcp handshake packets
void skip_handshake(HashTable table, struct parsed_packet pkt) {
  if (pkt.tcp.th_flags != TH_SYN && pkt.tcp.th_flags != TH_ACK &&
      pkt.tcp.th_flags != TH_FIN) {
    insert_packet(table, pkt);
  }
}
