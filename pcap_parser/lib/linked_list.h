#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include "flow_api.h"
#include <stdint.h>
#include <stdlib.h>

typedef struct Node {
  uint64_t key;
  void *value;
  struct Node *next;
} Node;

// Create a new node
Node *new_node(uint64_t key, void *value);
// Insert a new node into the list
void insert_node(Node **head, const uint64_t key, void *value);
// Search for a node with the given key
Node *search_node(const Node *head, const uint64_t key);
// Delete a node with the given key
void delete_node(Node *head, const uint64_t key);
// Free all nodes in the list
void free_list(Node *head);

#endif
