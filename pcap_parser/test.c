#include "lib/handler.h"
#include "lib/hash_table.h"
#include "lib/parsers.h"
#include <arpa/inet.h>
#include <bits/types/struct_timeval.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int const HASH_TABLE_SIZE = 50;

void get_packets(pcap_t *handler, char *output_path);
void save_to_CSV(FILE *fp, parsed_packet pkt, package frame,
                 struct pcap_pkthdr *header, long int init_sec,
                 long int init_usec);

int main(int argc, char *argv[]) {

  if (argc != 3) {
    printf("USAGE: ./test.o <pcap file name> <csv output file name>\n");
    exit(1);
  }

  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline(argv[1], errbuff);
  if (handler == NULL) {
    fprintf(stderr, "Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }
  get_packets(handler, argv[2]);
  pcap_close(handler);
  return 0;
}

void get_packets(pcap_t *handler, char *output_path) {

  // The header that pcap gives us
  struct pcap_pkthdr *header;

  // The actual packet
  u_char const *full_packet;

  int packetCount = 0;

  const char *path = output_path;
  const char *csv_header =
      "timestamp,srcip,sport,dstip,dsport,proto,state,bytes,ttl,service,"
      "win,stcpb,tcpflags";
  FILE *fp = fopen(path, "w");
  fprintf(fp, "%s\n", csv_header);

  /** HashTable table = create_hash_table(HASH_TABLE_SIZE); */

  long int init_sec, init_usec, i = 0;

  while (pcap_next_ex(handler, &header, &full_packet) >= 0) {

    // get time stamp
    if (i == 0) {
      init_sec = header->ts.tv_sec;
      init_usec = header->ts.tv_usec;
      printf("init time: %ld\n", init_sec);
    }
    i++;

    // Show the packet number
    printf("Packet # %i\n", ++packetCount);

    //--------------------------------------------------------------------------
    package frame = frame_dissector(full_packet, header);
    if (frame.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    package packet = link_dissector(frame);
    if (packet.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    package segment = network_dissector(packet);
    if (segment.is_valid == false) {
      goto END;
    }

    //--------------------------------------------------------------------------
    package payload = transport_demux(segment);
    if (payload.is_valid == false) {
      goto END;
    }

    // insert to hash table
    parsed_packet pkt = pkt_parser(frame, packet, segment, payload);
    save_to_CSV(fp, pkt, frame, header, init_sec, init_usec);
    /** insert_packet(table, pkt); */

  END:
    printf("-------------------------------------------------------------------"
           "----\n");
  }

  /** print_hashtable(table); */
  /** free_hash_table(table); */

  fclose(fp);
}

void save_to_CSV(FILE *fp, parsed_packet pkt, package frame,
                 struct pcap_pkthdr *header, long int init_sec,
                 long int init_usec) {
  char buf[64];
  snprintf(buf, sizeof buf, "%ld.%06ld", header->ts.tv_sec - init_sec,
           header->ts.tv_usec - init_usec);

  char *sip = strdup(inet_ntoa(pkt.ip_header.ip_src));
  char *dip = strdup(inet_ntoa(pkt.ip_header.ip_dst));

  if (pkt.ip_header.ip_p == IPPROTO_TCP) {

    fprintf(fp, "%s, %s, %d, %s, %d, %s, %d, %d, %d, %d, %d, %u, %d\n", buf,
            sip, pkt.tcp.source, dip, pkt.tcp.dest, "TCP", 0,
            frame.package_size, pkt.ip_header.ip_ttl, 0, pkt.tcp.th_win,
            pkt.tcp.seq, pkt.tcp.th_flags);
  } else {
    fprintf(fp, "%s, %s, %d, %s, %d, %s, %d, %d, %d, %d, %d, %u, %d\n", buf,
            sip, pkt.udp.source, dip, pkt.udp.dest, "UDP", 0,
            frame.package_size, pkt.ip_header.ip_ttl, 0, 0, 0, 0);
  }
}
