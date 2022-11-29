#include "hash_table.h"
#include "flow_api.h"
#include "linked_list.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}
HashTable newHashTable(const size_t size) {
  return (HashTable){size, malloc(size * sizeof(Node *))};
}

// insert a new Node into the hash table
void flow_insert(HashTable table, const uint64_t key, const flow_base_t flow) {

  uint index = hash(key, table.size);

  insert_node(&table.lists[index], new_flow_node(key, flow));
}

Node *new_flow_node(const uint64_t key, const flow_base_t flow) {

  Node *const node = malloc(sizeof(Node));
  // allocate memory for value
  node->value = malloc(sizeof(flow_base_t));
  // copy value to the new node
  memcpy(node->value, &flow, sizeof(flow_base_t));

  node->key = key;
  node->next = NULL;
  return node;
}

// search flow by a key in the hash table and return the flow
flow_base_t *flow_search(const HashTable table, const uint64_t key) {
  uint index = hash(key, table.size);
  Node *head_flow = table.lists[index];

  if (head_flow == NULL) {
    return NULL;
  }

  Node *n = search_node(head_flow, key);

  return n == NULL ? NULL : (flow_base_t *)n->value;
}

// free hash table
void freeHashTable(HashTable table) {
  for (uint i = 0; i < table.size; i++) {
    Node *head_flow = table.lists[i];
    if (head_flow != NULL) {
      free_list(head_flow);
    }
  }
  free(table.lists);
}

// remove a node from the hash table
void remove_flow(HashTable table, const uint key) {
  uint index = hash(key, table.size);
  Node *head = table.lists[index];

  if (head == NULL) {
    return;
  }

  delete_node(head, key);
}

// print the hash table
void print_hashtable(const HashTable table) {

  printf("**********HASH TABLE**********\n");
  for (uint i = 0; i < table.size; i++) {
    Node *head = table.lists[i];

    printf("Id [%d]: \n", i);
    print_flows(head);

    printf("\n");
  }
}

void print_flows(const Node *const head) {

  const Node *scaner = head;

  while (scaner != NULL) {
    printf("Key: %lu, ", scaner->key);
    print_flow(*(flow_base_t *)scaner->value);

    scaner = scaner->next;
  }
}

// print flow node
void print_flow(const flow_base_t flow) {
  // print ip addresses
  printf("src ip: %s,", inet_ntoa(flow.sip));
  printf("dst ip: %s,", inet_ntoa(flow.dip));

  // print port
  printf("src port: %d,", flow.sp);
  printf("dst port: %d\n", flow.dp);
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
