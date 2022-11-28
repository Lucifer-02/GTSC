#include "hash_table.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
HashTable newHashTable(size_t size) {
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
void removeNode(HashTable table, uint key) {
  uint index = hash(key, table.size);
  Node *current = table.lists[index];
  Node *prev = NULL;

  if (current != NULL && current->key == key) {
    table.lists[index] = current->next;
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
    Node *head = table.lists[i];

    print_list(head);

    printf("Id [%d]: \n", i);
    printf("\n");
  }
}

void print_list(const Node *head) {
  while (head != NULL) {
    printf("key: %ld ", head->key);
    // print ip addresses
    printf("src ip: %s, ", inet_ntoa((head->value).sip));
    printf("dst ip: %s, ", inet_ntoa((head->value).dip));

    // print port
    printf("src port: %d, ", (head->value).sp);
    printf("dst port: %d\n", (head->value).dp);

    head = head->next;
  }
}

// get number of nodes in hashtable
int count_nodes(const HashTable table) {

  int count = 0;
  Node *temp;

  for (size_t i = 0; i < table.size; i++) {
    temp = table.lists[i];
    while (temp != NULL) {

      count++;
      temp = temp->next;
    }
  }
  return count;
}
