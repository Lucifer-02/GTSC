#include "linked_list.h"
#include "flow_api.h"
#include <pcap.h>
#include <string.h>

/** // Insert a new node into the list */
/** void insert_node(Node **head, Node *new_node) { */
/**  */
/**   // Insert the node at the end of the list */
/**   Node *current = *head; */
/**  */
/**   if (current == NULL) { */
/**     *head = new_node; */
/**   } else { */
/**     while (current->next != NULL) { */
/**       current = current->next; */
/**     } */
/**     current->next = new_node; */
/**   } */
/** } */

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

// Delete a node with the given key
void delete_node(Node *head, uint64_t key) {
  Node *n = head;
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
    size++;
    n = n->next;
  }
  return size;
}

// insert and sort node by key in the list
void insert_node(Node **head, Node *new_node) {
  Node *current = *head;

  if (current == NULL) {
	*head = new_node;
  } else {
	if (current->key > new_node->key) {
	  new_node->next = current;
	  *head = new_node;
	} else {
	  while (current->next != NULL && current->next->key < new_node->key) {
		current = current->next;
	  }
	  new_node->next = current->next;
	  current->next = new_node;
	}
  }
}
