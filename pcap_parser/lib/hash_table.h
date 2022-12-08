#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "flow_api.h"
#include "linked_list.h"
#include "parsers.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  size_t size;
  Node **lists;
} HashTable;

// Hash function
uint hash(const uint64_t x, const size_t len);
HashTable create_hash_table(const size_t size);
Node *create_flow_node(const uint64_t key, const flow_base_t flow);
Node *create_payload_node(const struct parsed_packet pkt);
flow_base_t create_flow(const struct parsed_packet pkt);
void free_hash_table(HashTable table);
// insert a new flow into the hash table
void insert_new_flow(HashTable table, const uint64_t key, const flow_base_t flow);
// Insert a packet into a flow in the hash table
void insert_packet(HashTable table, const struct parsed_packet pkt);
// Insert a packet into a flow
void insert_to_flow(flow_base_t *flow, const struct parsed_packet pkt);
// search for a flow with the given key
flow_base_t *search_flow(const HashTable table, const uint64_t key);
// delete a flow with the given key
void delete_flow(HashTable table, const uint64_t key);
// Get number of packets in hash table
uint count_packets(const HashTable table);
// get number of flows in hash table
uint count_flows(const HashTable table);
void print_hashtable(const HashTable table);
void print_flows(const Node *head);
// print all packets in a flow
void print_flow(const flow_base_t flow);
Node **get_flow_direction(const flow_base_t *flow,
                          const struct parsed_packet pkt);
// get number of nodes in a flow
uint get_flow_size(const flow_base_t *flow);
// pop head packet node from a flow
struct parsed_payload pop_head_payload(Node **flow_diection);
// free a payload node and it's data in a flow
void free_payload(Node *payload_node);
// free all payload nodes in a flow
void free_flow(Node *flow_direction);
// print payload direction
void print_payload_direction(Node *head, bool is_up);

#endif
