#include <stdint.h>
#include <stdlib.h>

typedef struct node {
  uint64_t key;
  void *value;
  struct node *next;
} node;

// Create a new node
node *new_node(uint64_t key, void *value) {
  node *n = malloc(sizeof(node));
  n->key = key;
  n->value = value;
  n->next = NULL;
  return n;
}

// Insert a new node into the list
void insert(node *head, uint64_t key, void *value) {
  node *n = new_node(key, value);
  n->next = head->next;
  head->next = n;
}

// Search for a node with the given key
node *search(node *head, uint64_t key) {
  node *n = head->next;
  while (n != NULL) {
    if (n->key == key) {
      return n;
    }
    n = n->next;
  }
  return NULL;
}

// Delete a node with the given key
void delete (node *head, uint64_t key) {
  node *n = head;
  while (n->next != NULL) {
    if (n->next->key == key) {
      node *tmp = n->next;
      n->next = n->next->next;
      free(tmp);
      return;
    }
    n = n->next;
  }
}

// Free all nodes in the list
void free_list(node *head) {
  node *n = head->next;
  while (n != NULL) {
    node *tmp = n;
    n = n->next;
    free(tmp);
  }
  free(head);
}
