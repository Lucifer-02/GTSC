#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stdint.h>
#include <stdlib.h>

typedef struct Node {
  uint64_t key;
  void *value;
  struct Node *next;
} Node;

// Insert a new node into the list
void insert_node(Node **head, Node *new_node);
// Search for a node with the given key
Node *search_node(const Node *head, const uint64_t key);
// Delete a node with the given key
void delete_node(Node *head, const uint64_t key);
// Free all nodes in the list
void free_list(Node *head);

#endif
