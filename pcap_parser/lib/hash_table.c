#include "hash_table.h"
#include "flow_api.h"
#include "linked_list.h"
#include "parsers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
HashTable newHashTable(const size_t size) {
  return (HashTable){size, malloc(size * sizeof(Node *))};
}

// insert a new Node into the hash table
void flow_insert(HashTable table, const uint64_t key, const flow_base_t flow) {

  uint index = hash(key, table.size);

  insert_node(&table.lists[index], new_flow_node(key, flow));
}

Node *new_flow_node(const uint64_t key, const flow_base_t flow) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  node->value = malloc(sizeof(flow_base_t));
  // copy value to the new node
  memcpy(node->value, &flow, sizeof(flow_base_t));

  node->key = key;
  node->next = NULL;
  return node;
}

// search flow by a key in the hash table and return the flow
flow_base_t *flow_search(const HashTable table, const uint64_t key) {
  uint index = hash(key, table.size);
  Node *head_flow = table.lists[index];

  if (head_flow == NULL) {
    return NULL;
  }

  Node *n = search_node(head_flow, key);

  return n == NULL ? NULL : (flow_base_t *)n->value;
}

// free hash table
void freeHashTable(HashTable table) {
  for (uint i = 0; i < table.size; i++) {
    Node *flow_temp = table.lists[i];
    if (flow_temp != NULL) {

      // free each package nodes in each flow
      while (flow_temp != NULL) {
        Node *tmp = flow_temp;
        free_list(((flow_base_t *)tmp->value)->package_down);
        free_list(((flow_base_t *)tmp->value)->package_up);
        flow_temp = flow_temp->next;
      }
    }
    // free all flow nodes
    free_list(table.lists[i]);
  }
  free(table.lists);
}

// remove a node from the hash table
void remove_flow(HashTable table, const uint key) {
  uint index = hash(key, table.size);
  Node *head = table.lists[index];

  if (head == NULL) {
    return;
  }

  delete_node(head, key);
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
  printf("\t|ip: %s,", inet_ntoa(flow.sip));
  printf("ip: %s,", inet_ntoa(flow.dip));

  // print port
  printf("port: %d, ", flow.sp);
  printf("port: %d\n", flow.dp);

  // print expected sequence number
  printf("\t|expected seq DOWN: %u, ", flow.exp_seq_down);
  printf("expected seq UP: %u\n", flow.exp_seq_up);

  // print list of packets in the flow
  Node *temp_down = flow.package_down;
  while (temp_down != NULL) {

    printf("\t\t[DOWN] seq: %ld\n", temp_down->key);
    temp_down = temp_down->next;
  }

  Node *temp_up = flow.package_up;
  while (temp_up != NULL) {

    printf("\t\t[UP] seq: %ld\n", temp_up->key);
    temp_up = temp_up->next;
  }
}

// get number of flows in hashtable
uint count_flows(const HashTable table) {

  int count = 0;
  Node *temp;

  for (size_t i = 0; i < table.size; i++) {
    temp = table.lists[i];
    uint list_size = get_list_size(temp);
    count += list_size;
  }
  return count;
}

// Insert packet into the hash table
void packet_insert(HashTable table, const struct parsed_packet pkt) {

  uint64_t flow_key =
      pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.src_port + pkt.dst_port;

  // flow in hash table
  flow_base_t *flow = flow_search(table, flow_key);

  if (flow == NULL) {
    printf("flow not found, creating new one\n");

    flow_base_t new_flow = create_flow(pkt);
    insert_to_flow(&new_flow, pkt);
    flow_insert(table, flow_key, new_flow);

  } else {
    printf("flow found, inserting to it\n");
    insert_to_flow(flow, pkt);
  }
}

void insert_to_flow(flow_base_t *flow, const struct parsed_packet pkt) {
  // determine direction of the packet with respect to the flow
  if (pkt.src_ip.s_addr == flow->sip.s_addr) {
    if (pkt.type == IPPROTO_TCP) {
      flow->exp_seq_down = pkt.seq + pkt.payload.data_len;
    }
    insert_node(&flow->package_down, new_packet_node(pkt));

  } else {
    if (pkt.type == IPPROTO_TCP) {
      flow->exp_seq_up = pkt.seq + pkt.payload.data_len;
    }
    insert_node(&flow->package_up, new_packet_node(pkt));
  }
}

// create new flow
flow_base_t create_flow(const struct parsed_packet pkt) {

  return (flow_base_t){.sip = pkt.src_ip,
                       .dip = pkt.dst_ip,
                       .sp = pkt.src_port,
                       .dp = pkt.dst_port,
                       .ip_proto = pkt.type};
}

// create new packet node
Node *new_packet_node(const struct parsed_packet pkt) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  node->value = malloc(sizeof(struct parsed_payload));
  // copy value to the new node
  memcpy(node->value, &pkt, sizeof(struct parsed_payload));

  node->key = pkt.seq;
  node->next = NULL;
  return node;
}

// Get number of packets in hash table
uint count_packets(const HashTable table) {

  int count = 0;
  const Node *flow_temp;

  for (size_t i = 0; i < table.size; i++) {
    flow_temp = table.lists[i];
    while (flow_temp != NULL) {

      Node *packet_down_temp = ((flow_base_t *)flow_temp->value)->package_down;
      Node *packet_up_temp = ((flow_base_t *)flow_temp->value)->package_up;

      uint list_down_size = get_list_size(packet_down_temp);
      uint list_up_size = get_list_size(packet_up_temp);

      count += list_down_size + list_up_size;

      flow_temp = flow_temp->next;
    }
  }
  return count;
}

// remove packet from the hash table
void remove_packet(HashTable table, const uint key) {
  uint index = hash(key, table.size);
  Node *head = table.lists[index];

  if (head == NULL) {
    return;
  }

  Node *flow = search_node(head, key);

  if (flow == NULL) {
    return;
  }

  delete_node(((flow_base_t *)flow->value)->package_down, key);
}
