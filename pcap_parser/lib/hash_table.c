#include "hash_table.h"
#include "handler.h"
#include "parsers.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
// insert a new flow into the hash table
void insert_new_flow(HashTable table, Node *flow_node) {
  uint index = hash(flow_node->key, table.size);
  insert_first_node(&table.lists[index], flow_node);
}

// insert a packet data to a flow
void insert_to_flow(flow_base_t *flow, Node *pkt_node,
                              uint16_t protocol, Node **flow_direction) {
  if (protocol == IPPROTO_TCP) {
    insert_node_asc(flow_direction, pkt_node);
  } else {
    insert_first_node(flow_direction, pkt_node);
  }
}

// search flow by a key in the hapktsh table and return the flow
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
        free_flow(((flow_base_t *)tmp->value)->package_down);
        free_flow(((flow_base_t *)tmp->value)->package_up);
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
    free_flow(((flow_base_t *)n->value)->package_down);
    free_flow(((flow_base_t *)n->value)->package_up);
    table.lists[index] = n->next;
    free_node(n);
  } else {
    while (n->next != NULL) {
      if (n->next->key == key) {
        free_flow(((flow_base_t *)n->next->value)->package_down);
        free_flow(((flow_base_t *)n->next->value)->package_up);
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
  free_payload(node);
  return payload;
}

// free a payload node and it's data in a flow
void free_payload(Node *payload_node) {
  // free payload data
  free((u_char *)((struct parsed_payload *)payload_node->value)->data);
  free_node(payload_node);
}

// free all payload nodes in a flow
void free_flow(Node *flow_direction) {

  Node *temp = flow_direction;
  while (temp != NULL) {
    Node *next = temp->next;
    free_payload(temp);
    temp = next;
  }
}
