#include "handler.h"
#include <assert.h>
#include <string.h>

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt) {

  printf("inserting packet \n");

  uint64_t flow_key;

  if (pkt.protocol == IPPROTO_TCP) {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.tcp.source + pkt.tcp.dest;
    insert_tcp_pkt(table, flow_key, pkt);
  }

  if (pkt.protocol == IPPROTO_UDP) {
    flow_key =
        pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.udp.source + pkt.udp.dest;
    insert_udp_pkt(table, flow_key, pkt);
  }
}

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt) {
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

    // skip unnecessary processing packets
  } else if (pkt.tcp.th_flags == 0x18) {
    printf("flow found, inserting to it\n");
    Node *new_pkt_node = create_payload_node(pkt);
    insert_to_flow(new_pkt_node, DESC, get_flow_direction(flow, pkt));
  }
}

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt) {

  flow_base_t *flow = search_flow(table, flow_key);
  Node *new_pkt_node = create_payload_node(pkt);

  if (flow == NULL) {
    printf("flow not found, creating new one\n");

    flow_base_t new_flow = create_flow(pkt);
    insert_to_flow(new_pkt_node, FIRST, get_flow_direction(&new_flow, pkt));
    insert_new_flow(table, create_flow_node(flow_key, new_flow));
    printf("new flow created\n");

  } else {
    printf("flow found, inserting to it\n");
    insert_to_flow(new_pkt_node, FIRST, get_flow_direction(flow, pkt));
  }
}

// print the hash table
void print_hashtable(HashTable const table) {

  printf("**********HASH TABLE**********\n");
  for (uint i = 0; i < table.size; i++) {
    Node *head = table.lists[i];
    printf("Id [%d]: \n", i);
    print_flows(head);
    printf("\n");
  }
}

void print_flows(Node const *const head) {

  const Node *scaner = head;

  while (scaner != NULL) {
    printf("Key: %lu:\n", scaner->key);
    print_flow(*(flow_base_t *)scaner->value);
    scaner = scaner->next;
  }
}

// print flow info like src ip, dst ip, src port, dst port, protocol and payload
void print_flow(flow_base_t flow) {
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
  print_flow_direction(flow.flow_up, true);
  print_flow_direction(flow.flow_down, false);
}

// print payload in a flow direction
void print_flow_direction(Node const *head, bool is_up) {

  Node const *temp = head;
  char const *direction = is_up ? "UP" : "DOWN";

  while (temp != NULL) {

    printf("\t\t[%s] ", direction);
    printf("Seq: %ld, data size: %d\n", temp->key,
           ((parsed_payload *)temp->value)->data_len);

	print_payload(((parsed_payload *)temp->value)->data,
				  ((parsed_payload *)temp->value)->data_len);
	printf("\t\t---------------------------------------------------------------"
		   "----"
		   "----\n");

    temp = temp->next;
  }
}


// create new packet node
Node *create_payload_node(parsed_packet pkt) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  parsed_payload *value = malloc(sizeof(parsed_payload));
  assert(value != NULL);

  // allocate memory for payload
  u_char *const payload = malloc(pkt.payload.data_len);
  memcpy(payload, pkt.payload.data, pkt.payload.data_len);

  // copy payload to value
  *value = (parsed_payload){.data = payload, .data_len = pkt.payload.data_len};

  // move packet data to node
  node->value = value;
  node->key = pkt.protocol == IPPROTO_TCP ? pkt.tcp.seq : 0;
  node->next = NULL;

  return node;
}

Node *create_flow_node(uint64_t key, flow_base_t flow) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  node->value = malloc(sizeof(flow_base_t));
  assert(node->value != NULL);

  // copy value to the new node
  memcpy(node->value, &flow, sizeof(flow_base_t));

  node->key = key;
  node->next = NULL;
  return node;
}

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt) {

  return pkt.protocol == IPPROTO_TCP
			 ? (flow_base_t){
				   .sip = pkt.src_ip,
				   .dip = pkt.dst_ip,
				   .sp= pkt.tcp.source,
				   .dp= pkt.tcp.dest,
				   .ip_proto = pkt.protocol,
				   .flow_up = NULL,
				   .flow_down = NULL,
			   }
			 : (flow_base_t){
				   .sip = pkt.src_ip,
				   .dip = pkt.dst_ip,
				   .sp= pkt.udp.source,
				   .dp= pkt.udp.dest,
				   .ip_proto = pkt.protocol,
				   .flow_up = NULL,
				   .flow_down = NULL,
			   };
}

// get flow direction by compare src ip of the packet with the flow
Node **get_flow_direction(flow_base_t const *flow, parsed_packet pkt) {
  return pkt.src_ip.s_addr == flow->sip.s_addr ? (Node **)(&flow->flow_up)
                                               : (Node **)(&flow->flow_down);
}

/*
 * print package payload data (avoid printing binary data)
 */
void print_payload(u_char const *payload, uint payload_size) {

  /** if (payload_size > 0) { */
  /**   printf("\t\tpayload size: %u bytes\n", payload_size); */
  /** } else { */
  /**   printf("\t\tpayload size: 0 bytes\n"); */
  /**   return; */
  /** } */

  printf("\n");

  int len = payload_size;
  int len_rem = payload_size;
  int line_width = 11; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  u_char const *ch = payload;

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

void print_hex_ascii_line(u_char const *const payload, int len, int offset) {

  int gap;
  u_char const *ch;

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
