#include "hash_table.h"
#include "flow_api.h"
#include "linked_list.h"
#include "parsers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
// create a new hash table with all entries NULL
HashTable create_hash_table(const size_t size) {
  return (HashTable){size, malloc(size * sizeof(Node *))};
}

// create new packet node
Node *create_packet_node(const struct parsed_packet pkt) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  node->value = malloc(sizeof(struct parsed_payload));
  // copy value to the new node
  memcpy(node->value, &pkt.payload, sizeof(struct parsed_payload));

  node->key = pkt.seq;
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
// insert a new Node into the hash table
void insert_flow(HashTable table, const uint64_t key, const flow_base_t flow) {

  uint index = hash(key, table.size);

  insert_node(&table.lists[index], create_flow_node(key, flow));
}

// insert a packet data to a flow
void insert_to_flow(flow_base_t *flow, const struct parsed_packet pkt) {
  insert_node((get_flow_direction(flow, pkt)), create_packet_node(pkt));
}

// search flow by a key in the hash table and return the flow
flow_base_t *search_flow(const HashTable table, const uint64_t key) {
  uint index = hash(key, table.size);
  Node *head_flow = table.lists[index];

  if (head_flow == NULL) {
    return NULL;
  }

  Node *n = search_node(head_flow, key);

  return n == NULL ? NULL : (flow_base_t *)n->value;
}

// free hash table
void free_hash_table(HashTable table) {
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

// remove flow from hash table
void delete_flow(HashTable table, const uint64_t key) {

  uint index = hash(key, table.size);

  Node *n = table.lists[index];

  if (n == NULL) {
    return;
  }

  // find the flow node by key then free all package nodes in the flow, then
  // delete flow node
  if (n->key == key) {
    free_list(((flow_base_t *)n->value)->package_down);
    free_list(((flow_base_t *)n->value)->package_up);
    table.lists[index] = n->next;
    free_node(n);
  } else {
    while (n->next != NULL) {
      if (n->next->key == key) {
        free_list(((flow_base_t *)n->next->value)->package_down);
        free_list(((flow_base_t *)n->next->value)->package_up);
        Node *tmp = n->next;
        n->next = n->next->next;
        free_node(tmp);
        return;
      }
      n = n->next;
    }
  }
  printf("flow with key %ld not found to delete\n", key);
}

// Insert packet into the hash table
void insert_packet(HashTable table, const struct parsed_packet pkt) {

  printf("inserting packet \n");
  uint64_t flow_key =
      pkt.src_ip.s_addr + pkt.dst_ip.s_addr + pkt.src_port + pkt.dst_port;

  // flow in hash table
  flow_base_t *flow = search_flow(table, flow_key);

  if (flow == NULL) {
    printf("flow not found, creating new one\n");

    flow_base_t new_flow = create_flow(pkt);
    insert_to_flow(&new_flow, pkt);
    insert_flow(table, flow_key, new_flow);

  } else {
    printf("flow found, inserting to it\n");
    insert_to_flow(flow, pkt);
  }
}

Node **get_flow_direction(const flow_base_t *flow,
                          const struct parsed_packet pkt) {
  // This cast may be unsafe because discards const
  return pkt.src_ip.s_addr == flow->sip.s_addr ? (Node **)(&flow->package_up)
                                               : (Node **)(&flow->package_down);
}

// create new flow
flow_base_t create_flow(const struct parsed_packet pkt) {

  return (flow_base_t){.sip = pkt.src_ip,
                       .dip = pkt.dst_ip,
                       .sp = pkt.src_port,
                       .dp = pkt.dst_port,
                       .ip_proto = pkt.type};
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

  // print expected sequence number
  printf("\t|exp seq DOWN: %u, ", flow.exp_seq_down);
  printf("exp seq UP: %u\n", flow.exp_seq_up);

  // print list of packets in the flow
  Node *temp_down = flow.package_down;
  while (temp_down != NULL) {

    printf("\t\t[DOWN] seq: %ld, data size: %d\n", temp_down->key,
           ((struct parsed_payload *)temp_down->value)->data_len);
    temp_down = temp_down->next;
  }

  Node *temp_up = flow.package_up;
  while (temp_up != NULL) {

    printf("\t\t[UP] seq: %ld, data size: %d\n", temp_up->key,
           ((struct parsed_payload *)temp_up->value)->data_len);
    temp_up = temp_up->next;
  }
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

// get number of nodes in a flow
uint get_flow_size(const flow_base_t *flow) {

  uint list_down_size = get_list_size(flow->package_down);
  uint list_up_size = get_list_size(flow->package_up);

  return list_down_size + list_up_size;
}

// pop head packet node from a flow
struct parsed_payload pop_head_payload(Node **flow_direction) {

  Node *node = pop_first_node(flow_direction);
  if (node == NULL) {
    printf("flow is empty, nothing to delete\n");
  }

  struct parsed_payload payload = *(struct parsed_payload *)node->value;

  free_node(node);

  return payload;
}
