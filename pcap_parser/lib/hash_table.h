#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "flow_api.h"
#include "linked_list.h"
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
int count_nodes(const HashTable table);
void print_flows(const Node *head);
// insert a new flow into the hash table
void flow_insert(HashTable table, const uint64_t key, flow_base_t flow);

flow_base_t *flow_search(const HashTable table, const uint64_t key);

void print_flow(const flow_base_t flow);
void remove_flow(HashTable table, const uint key);
#endif
