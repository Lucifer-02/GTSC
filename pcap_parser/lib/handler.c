#include "handler.h"

// classify and insert a new packet into hash table
void prepare_insert(HashTable table, struct parsed_packet pkt) {

  printf("inserting packet \n");

  uint64_t flow_key;

  if (pkt.protocol == IPPROTO_TCP) {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.tcp.source + pkt.tcp.dest;
    flow_base_t *flow = search_flow(table, flow_key);

    if (flow == NULL) {
      printf("flow not found, creating new one if it is SYN\n");

      // create new flow if it is SYN
      if (pkt.tcp.th_flags == TH_SYN) {
        flow_base_t new_flow = create_flow(pkt);
        insert_new_flow(table, flow_key, new_flow);
        printf("new flow created\n");
      } else {
        printf("packet is not SYN, ignoring\n");
      }

    } else if (pkt.tcp.th_flags != TH_ACK) {
      printf("flow found, inserting to it\n");
      insert_to_flow(flow, pkt);
    }
  } else {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.udp.source + pkt.udp.dest;
    flow_base_t *flow = search_flow(table, flow_key);
    if (flow == NULL) {
      printf("flow not found, creating new one if it is SYN\n");

      flow_base_t new_flow = create_flow(pkt);
      insert_new_flow(table, flow_key, new_flow);
      printf("new flow created\n");

    } else {
      printf("flow found, inserting to it\n");
      insert_to_flow(flow, pkt);
    }
  }
}
