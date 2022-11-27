#include "../lib/flow_api.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
  uint key;
  flow_base_t value;
  struct Node *next;
} Node;

typedef struct {
  uint size;
  Node **lists;
} HashTable;

// Hash function
uint hash(uint x, size_t len);
// create a new hash table
HashTable newHashTable(uint size);
// search for a key in the hash table, return list of node
Node *search(HashTable table, uint key);
// print search result
void printSearchResult(const Node *node);
// free list of node
void freeList(Node *node);
// free hash table
void freeHashTable(HashTable table);
// remove a node from the hash table
void removeNode(HashTable *table, uint key);
// insert a new key-value pair into the hash table
void insert(HashTable table, uint key, flow_base_t value);
// print the hash table
void printHashTable(const HashTable table);

int main() {
  // create a new hash table
  HashTable table = newHashTable(20);

  // create keys and values
  flow_base_t v1 = (flow_base_t){
      .dip.s_addr = 11, .sip.s_addr = 12, .dp = 13, .sp = 14, .ip_proto = 122};
  uint k1 = v1.dip.s_addr + v1.sip.s_addr + v1.dp + v1.sp;

  flow_base_t v2 = (flow_base_t){
      .dip.s_addr = 21, .sip.s_addr = 22, .dp = 23, .sp = 24, .ip_proto = 42};
  uint k2 = v2.dip.s_addr + v2.sip.s_addr + v2.dp + v2.sp;

  flow_base_t v3 = (flow_base_t){
      .dip.s_addr = 31, .sip.s_addr = 32, .dp = 33, .sp = 34, .ip_proto = 42};
  uint k3 = v3.dip.s_addr + v3.sip.s_addr + v3.dp + v3.sp;

  // insert some values
  insert(table, k1, v1);
  insert(table, k2, v2);

  // print the hash table
  printHashTable(table);

  insert(table, k3, v3);
  insert(table, k3, v3);

  // print the hash table
  printHashTable(table);

  // remove a node
  removeNode(&table, k3);

  // print the hash table
  printHashTable(table);

  // search for a key
  Node *node = search(table, k2);
  printSearchResult(node);

  // free the hash table
  freeHashTable(table);

  return 0;
}

// hash function
uint hash(uint x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
HashTable newHashTable(uint size) {
  return (HashTable){size, malloc(size * sizeof(Node *))};
}

// insert a new key-value pair into the hash table
void insert(HashTable table, uint key, flow_base_t value) {

  uint index = hash(key, table.size);

  Node *node = malloc(sizeof(Node));
  node->key = key;
  node->value = value;
  node->next = NULL;

  Node *current = table.lists[index];
  if (current == NULL) {
    table.lists[index] = node;
  } else {
    while (current->next != NULL) {
      current = current->next;
    }
    current->next = node;
  }
}

// search for a key in the hash table, return list of node
Node *search(HashTable table, uint key) {
  uint index = hash(key, table.size);
  Node *current = table.lists[index];

  if (current != NULL && current->key == key) {
    return current;
  }

  return NULL;
}

// print search result
void printSearchResult(const Node *node) {
  if (node == NULL) {
    printf("key not found\n");
  } else {
    for (const Node *current = node; current != NULL; current = current->next) {
      printf("key: %d, value: %c\n", current->key, current->value);
    }
  }
}

// free list of node
void freeList(Node *node) {
  if (node == NULL) {
    return;
  }

  freeList(node->next);
  free(node);
}

// free hash table
void freeHashTable(HashTable table) {
  for (uint i = 0; i < table.size; i++) {
    freeList(table.lists[i]);
  }
  free(table.lists);
}

// remove a node from the hash table
void removeNode(HashTable *table, uint key) {
  uint index = hash(key, table->size);
  Node *current = table->lists[index];
  Node *prev = NULL;

  if (current != NULL && current->key == key) {
    table->lists[index] = current->next;
    free(current);
    return;
  }

  while (current != NULL && current->key != key) {
    prev = current;
    current = current->next;
  }

  if (current == NULL) {
    return;
  }

  prev->next = current->next;
  free(current);
}

// print the hash table
void printHashTable(const HashTable table) {

  printf("**********HASH TABLE**********\n");
  for (uint i = 0; i < table.size; i++) {
    Node *current = table.lists[i];

    printf("Id [%d]: \n", i);
    while (current != NULL) {
      printf("key: %d:", current->key);
      printf("value: %d:\n", current->value.dip.s_addr);
      current = current->next;
    }
    printf("\n");
  }
}
