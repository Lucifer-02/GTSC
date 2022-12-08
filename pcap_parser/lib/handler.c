#include "handler.h"
#include "hash_table.h"
#include <stdint.h>
#include <string.h>

// classify and insert a new packet into hash table
void prepare_insert(HashTable table, struct parsed_packet pkt) {

  printf("inserting packet \n");

  uint64_t flow_key;

  if (pkt.protocol == IPPROTO_TCP) {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.tcp.source + pkt.tcp.dest;
	insert_tcp_pkt(table,flow_key,pkt);
  } else {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.udp.source + pkt.udp.dest;
	insert_udp_pkt(table,flow_key,pkt);
  }
}

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key,
                    struct parsed_packet pkt) {
  flow_base_t *flow = search_flow(table, flow_key);

  if (flow == NULL) {
    printf("flow not found, creating new one if it is SYN\n");

    // create new flow if it is SYN
    if (pkt.tcp.th_flags == TH_SYN) {
      flow_base_t new_flow = create_flow(pkt);
      insert_new_flow(table, create_flow_node(flow_key, new_flow));
      printf("new flow created\n");
    } else {
      printf("packet is not SYN, ignoring\n");
    }

  } else if (pkt.tcp.th_flags != TH_ACK) {
    printf("flow found, inserting to it\n");
    Node *new_pkt_node = create_payload_node(pkt);
    insert_to_flow(flow, new_pkt_node, pkt.protocol,
                   get_flow_direction(flow, pkt));
  }
}

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key,
					struct parsed_packet pkt) {
  flow_base_t *flow = search_flow(table, flow_key);

  if (flow == NULL) {
	printf("flow not found, creating new one\n");

	flow_base_t new_flow = create_flow(pkt);
	insert_new_flow(table, create_flow_node(flow_key, new_flow));
	printf("new flow created\n");

  } else {
	printf("flow found, inserting to it\n");
	Node *new_pkt_node = create_payload_node(pkt);
	insert_to_flow(flow, new_pkt_node, pkt.protocol,
				   get_flow_direction(flow, pkt));
  }
}

// print the hash table
void print_hashtable(const HashTable table) {

  printf("**********HASH TABLE**********\n");
  for (uint i = 0; i < table.size; i++) {
    Node *head = table.lists[i];
    printf("Id [%d]: \n", i);
    print_flows(head);
    printf("\n");
  }
}

void print_flows(const Node *const head) {

  const Node *scaner = head;

  while (scaner != NULL) {
    printf("Key: %lu:\n", scaner->key);
    print_flow(*(flow_base_t *)scaner->value);
    scaner = scaner->next;
  }
}

// print flow node
void print_flow(const flow_base_t flow) {
  // print ip addresses
  printf("\t|ip: %s", inet_ntoa(flow.sip));
  printf(" <=> %s, ", inet_ntoa(flow.dip));

  // print port
  printf("port: %d", flow.sp);
  printf(" <=> %d\n", flow.dp);

  if (flow.ip_proto == IPPROTO_TCP) {
    printf("\t|Protocol: TCP\n");

    // print expected sequence number
    printf("\t|exp seq DOWN: %u, ", flow.exp_seq_down);
    printf("exp seq UP: %u\n", flow.exp_seq_up);
  } else {
    printf("\t|Protocol: UDP\n");
  }

  // print list of packets in the flow
  print_payload_direction(flow.package_up, true);
  print_payload_direction(flow.package_down, false);
}

// print payload direction
void print_payload_direction(Node *head, bool is_up) {

  Node *temp = head;
  const char *direction = is_up ? "UP" : "DOWN";

  while (temp != NULL) {

    printf("\t\t[%s] ", direction);
    printf("Seq: %ld, data size: %d\n", temp->key,
           ((struct parsed_payload *)temp->value)->data_len);
    print_payload(((struct parsed_payload *)temp->value)->data,
                  ((struct parsed_payload *)temp->value)->data_len);
    printf("\t\t---------------------------------------------------------------"
           "----"
           "----\n");
    temp = temp->next;
  }
}

// create a new hash table with all entries NULL
HashTable create_hash_table(const size_t size) {
  return (HashTable){size, calloc(size, sizeof(Node *))};
}

// create new packet node
Node *create_payload_node(const struct parsed_packet pkt) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  struct parsed_payload *value = malloc(sizeof(struct parsed_payload));

  // allocate memory for payload
  u_char *const payload = malloc(pkt.payload.data_len);
  memcpy(payload, pkt.payload.data, pkt.payload.data_len);

  // copy payload to value
  *value = (struct parsed_payload){.data = payload,
                                   .data_len = pkt.payload.data_len};

  // copy data to node
  node->value = value;
  node->key = pkt.protocol == IPPROTO_TCP ? pkt.tcp.seq : 0;
  node->next = NULL;

  return node;
}

Node *create_flow_node(const uint64_t key, const flow_base_t flow) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  node->value = malloc(sizeof(flow_base_t));
  // copy value to the new node
  memcpy(node->value, &flow, sizeof(flow_base_t));

  node->key = key;
  node->next = NULL;
  return node;
}

// create new flow
flow_base_t create_flow(const struct parsed_packet pkt) {

  return pkt.protocol == IPPROTO_TCP
			 ? (flow_base_t){
				   .sip = pkt.src_ip,
				   .dip = pkt.dst_ip,
				   .sp= pkt.tcp.source,
				   .dp= pkt.tcp.dest,
				   .ip_proto = pkt.protocol,
				   .package_up = NULL,
				   .package_down = NULL,
			   }
			 : (flow_base_t){
				   .sip = pkt.src_ip,
				   .dip = pkt.dst_ip,
				   .sp= pkt.udp.source,
				   .dp= pkt.udp.dest,
				   .ip_proto = pkt.protocol,
				   .package_up = NULL,
				   .package_down = NULL,
			   };
}

Node **get_flow_direction(const flow_base_t *flow,
                          const struct parsed_packet pkt) {
  // This cast may be unsafe because discards const
  return pkt.src_ip.s_addr == flow->sip.s_addr ? (Node **)(&flow->package_up)
                                               : (Node **)(&flow->package_down);
}
