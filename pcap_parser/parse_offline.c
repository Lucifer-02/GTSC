#include "lib/dissection.h"
#include <pcap.h>
#include <stdio.h>

void get_packets(pcap_t *handler);

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

  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    // Show the packet number
    printf("Packet # %i\n", ++packetCount);

    // Parse the packet
    const package frame = frame_dissect(packet, header);
    if (frame.is_valid == false) {
      continue;
    }

    const package packet = link_dissect(frame);
    if (packet.header_pointer == false) {
      continue;
    }

    const package segment = network_dissect(packet);
    if (segment.header_pointer == false) {
      continue;
    }

    const package payload = transport_demux(segment);
    if (payload.header_pointer == false) {
      continue;
    }

    // Show the packet
    print_payload(payload);
  }
}
