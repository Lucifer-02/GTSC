#include "linked_list.h"
#include "flow_api.h"
#include <pcap.h>
#include <string.h>

// Create a new node
Node *new_node(const uint64_t key, void *value) {
  Node *n = malloc(sizeof(Node));
  // allocate memory for value
  n->value = malloc(sizeof(flow_base_t));
  // copy value to the new node
  memcpy(n->value, value, sizeof(flow_base_t));
  n->key = key;
  n->next = NULL;
  return n;
}

// Insert a new node into the list
void insert_node(Node **head, const uint64_t key, void *value) {
  // Create a new node
  Node *node = new_node(key, value);

  // Insert the node at the end of the list
  Node *current = *head;

  if (current == NULL) {
    printf("current is null\n");
    *head = node;
  } else {
    while (current->next != NULL) {
      current = current->next;
    }
    current->next = node;
  }
}

// Search for a node with the given key
Node *search_node(const Node *head, const uint64_t key) {
  Node *n = head->next;
  while (n != NULL) {
    if (n->key == key) {
      return n;
    }
    n = n->next;
  }
  return NULL;
}

// Delete a node with the given key
void delete_node(Node *head, uint64_t key) {
  Node *n = head;
  while (n->next != NULL) {
    if (n->next->key == key) {
      Node *tmp = n->next;
      n->next = n->next->next;
      free(tmp);
      return;
    }
    n = n->next;
  }
}

// Free all nodes in the list
void free_list(Node *head) {
  Node *n = head->next;
  while (n != NULL) {
    Node *tmp = n;
    n = n->next;
    free(tmp);
  }
  free(head);
}
