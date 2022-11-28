#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "flow_api.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
  uint64_t key;
  flow_base_t value;
  struct Node *next;
} Node;

typedef struct {
  size_t size;
  Node **lists;
} HashTable;

// Hash function
uint hash(uint64_t x, size_t len);
// create a new hash table
HashTable newHashTable(size_t size);
// search for a key in the hash table, return list of node
Node *search(HashTable table, uint key);
// free list of node
void freeList(Node *node);
// free hash table
void freeHashTable(HashTable table);
// remove a node from the hash table
void removeNode(HashTable table, uint key);
// insert a new key-value pair into the hash table
void insert(HashTable table, uint key, flow_base_t value);
// print the hash table
void printHashTable(const HashTable table);
// print all node in list
void print_list(const Node *head);
// get number of node in hash table
int count_nodes(const HashTable table);

#endif
