#include "linked_list.h"
#include "flow_api.h"
#include <pcap.h>
#include <string.h>

// Search for a node with the given key
Node *search_node(const Node *head, const uint64_t key) {
  const Node *current = head;
  while (current != NULL) {
    if (current->key == key) {
      return (Node *)current;
    }
    current = current->next;
  }
  return NULL;
}

// Delete a node in list with the given key include the head node
void delete_node(Node **head, uint64_t key) {
  Node *n = *head;
  if (n == NULL) {
    return;
  }
  printf("this 1\n");
  if (n->key == key) {
    Node *tmp = n;
    *head = n->next;
    free_node(tmp);
    return;
  }
  while (n->next != NULL) {
    if (n->next->key == key) {
      Node *tmp = n->next;
      n->next = tmp->next;
      free_node(tmp);
      printf("Delete success\n");
      return;
    }
    n = n->next;
  }
  printf("Node with key %lu not found\n", key);
}

// Free all nodes in the list
void free_list(Node *head) {
  Node *n = head;
  while (n != NULL) {
    Node *tmp = n;
    n = n->next;
    free_node(tmp);
  }
}

// free node
void free_node(Node *node) {
  free(node->value);
  free(node);
}

// Get number of nodes in the list
uint get_list_size(const Node *head) {
  uint size = 0;
  const Node *n = head;
  while (n != NULL) {
    n = n->next;
    size++;
  }
  return size;
}

// insert node by order desc (key) in the list
void insert_node_desc(Node **head, Node *node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  if (n->key < node->key) {
    node->next = n;
    *head = node;
    return;
  }
  while (n->next != NULL) {
    if (n->next->key < node->key) {
      node->next = n->next;
      n->next = node;
      return;
    }
    n = n->next;
  }
  n->next = node;
}

// insert node by order asc (key) in the list
void insert_node_asc(Node **head, Node *node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  if (n->key > node->key) {
    node->next = n;
    *head = node;
    return;
  }
  while (n->next != NULL) {
    if (n->next->key > node->key) {
      node->next = n->next;
      n->next = node;
      return;
    }
    n = n->next;
  }
  n->next = node;
}

// insert end of list
void insert_last_node(Node **head, Node *node) {

  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  while (n->next != NULL) {
    n = n->next;
  }
  n->next = node;
}

// insert head of list
void insert_first_node(Node **head, Node *node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  node->next = n;
  *head = node;
}

// pop the first node in the list
Node *pop_first_node(Node **head) {
  Node *n = *head;
  if (n == NULL) {
    return NULL;
  }
  *head = n->next;
  return n;
}
