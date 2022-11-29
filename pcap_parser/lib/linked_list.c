#include "linked_list.h"
#include "flow_api.h"
#include <pcap.h>
#include <string.h>

// Insert a new node into the list
void insert_node(Node **head, Node *new_node) {

  // Insert the node at the end of the list
  Node *current = *head;

  if (current == NULL) {
    printf("current is null\n");
    *head = new_node;
  } else {
    while (current->next != NULL) {
      current = current->next;
    }
    current->next = new_node;
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
