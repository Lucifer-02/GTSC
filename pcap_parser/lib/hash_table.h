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
// create a new hash table
HashTable newHashTable(const size_t size);
// free hash table
void freeHashTable(HashTable table);
// print the hash table
void print_hashtable(const HashTable table);
// get number of node in hash table
uint count_flows(const HashTable table);
void print_flows(const Node *head);
// insert a new flow into the hash table
void flow_insert(HashTable table, const uint64_t key, const flow_base_t flow);
// search for a flow with the given key
flow_base_t *flow_search(const HashTable table, const uint64_t key);
// print a flow
void print_flow(const flow_base_t flow);
// delete a flow with the given key
void remove_flow(HashTable table, const uint key);
// create a new flow node
Node *new_flow_node(const uint64_t key, const flow_base_t flow);
// search for a flow node with the given key
flow_base_t *flow_search(const HashTable table, const uint64_t key);
// create new flow
flow_base_t create_flow(const struct parsed_packet pkt);
// Insert packet into the hash table
void packet_insert(HashTable table, const struct parsed_packet pkt);
// create new packet node
Node *new_packet_node(const struct parsed_packet pkt);
// Get number of packets in hash table
uint count_packets(const HashTable table);

#endif
