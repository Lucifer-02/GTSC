#include "hash_table.h"
#include <stdio.h>
#include <assert.h>

// hash function
uint hash(uint64_t x, size_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x % len;
}

// create a new hash table with all entries 0
HashTable create_hash_table(size_t size) {
  HashTable table = {size, calloc(size, sizeof(Node *))};
  assert(table.lists != NULL);
  return table;
}

// insert a new flow into the hash table
void insert_new_flow(HashTable table, Node *const flow_node) {
  uint index = hash(flow_node->key, table.size);
  insert_first_node(&table.lists[index], flow_node);
}

// insert a packet data to a flow
void insert_to_flow(Node *const pkt_node, enum InsertAlgorihm insert_type,
                    Node **flow_direction) {
  if (insert_type == DESC) {
    insert_node_desc(flow_direction, pkt_node);
  }

  if (insert_type == ASC) {
    insert_node_asc(flow_direction, pkt_node);
  }

  if (insert_type == FIRST) {
    insert_first_node(flow_direction, pkt_node);
  }
}

// search flow by key in the hash table
flow_base_t *search_flow(HashTable const table, uint64_t key) {

  uint index = hash(key, table.size);
  Node *head_flow = table.lists[index];

  if (head_flow == NULL) {
    return NULL;
  }

  Node *n = search_node(head_flow, key);
  return n == NULL ? NULL : (flow_base_t *)n->value;
}

// free hash table
void free_hash_table(HashTable table) {
  for (uint i = 0; i < table.size; i++) {
    Node *flow_temp = table.lists[i];
    if (flow_temp != NULL) {

      // free each package nodes in each flow
      while (flow_temp != NULL) {
        Node *tmp = flow_temp;
        free_flow_direction(((flow_base_t *)tmp->value)->flow_down);
        free_flow_direction(((flow_base_t *)tmp->value)->flow_up);
        flow_temp = flow_temp->next;
      }
    }
    // free all flow nodes
    free_list(table.lists[i]);
  }
  free(table.lists);
}

// remove flow from hash table
void delete_flow(HashTable table, uint64_t key) {

  uint index = hash(key, table.size);
  Node *n = table.lists[index];

  if (n == NULL) {
    return;
  }

  // find the flow node by key then free all package nodes in the flow, then
  // delete flow node
  if (n->key == key) {
    free_flow_direction(((flow_base_t *)n->value)->flow_down);
    free_flow_direction(((flow_base_t *)n->value)->flow_up);
    table.lists[index] = n->next;
    free_node(n);
  } else {
    while (n->next != NULL) {
      if (n->next->key == key) {
        free_flow_direction(((flow_base_t *)n->next->value)->flow_down);
        free_flow_direction(((flow_base_t *)n->next->value)->flow_up);
        Node *tmp = n->next;
        n->next = n->next->next;
        free_node(tmp);
        return;
      }
      n = n->next;
    }
  }
  printf("flow with key %ld not found to delete\n", key);
}

// Get number of packets in hash table
uint count_packets(HashTable const table) {

  int count = 0;
  Node const *flow_temp;

  for (size_t i = 0; i < table.size; i++) {
    flow_temp = table.lists[i];
    while (flow_temp != NULL) {

      Node *flow_down_temp = ((flow_base_t *)flow_temp->value)->flow_down;
      Node *flow_up_temp = ((flow_base_t *)flow_temp->value)->flow_up;

      uint flow_down_size = get_list_size(flow_down_temp);
      uint flow_up_size = get_list_size(flow_up_temp);

      count += flow_down_size + flow_up_size;
      flow_temp = flow_temp->next;
    }
  }
  return count;
}

// get number of flows in hashtable
uint count_flows(HashTable const table) {

  int count = 0;
  Node *temp;

  for (size_t i = 0; i < table.size; i++) {
    temp = table.lists[i];
    uint list_size = get_list_size(temp);
    count += list_size;
  }

  return count;
}

// get number of nodes in a flow
uint get_flow_size(flow_base_t const *flow) {
  uint list_down_size = get_list_size(flow->flow_down);
  uint list_up_size = get_list_size(flow->flow_up);
  return list_down_size + list_up_size;
}

// pop head node value from a flow
parsed_payload pop_head_payload(Node **flow_direction) {

  Node *node = pop_first_node(flow_direction);

  if (node == NULL) {
    printf("flow is empty, nothing to delete\n");
  }

  parsed_payload payload = *(parsed_payload *)node->value;
  free_payload_node(node);
  return payload;
}

// free a node value and it's data in a flow
void free_payload_node(Node *payload_node) {
  // free payload data
  free((u_char *)((parsed_payload *)payload_node->value)->data);
  free_node(payload_node);
}

// free all nodes in a flow
void free_flow_direction(Node *flow_direction) {

  Node *temp = flow_direction;
  while (temp != NULL) {
    Node *next = temp->next;
    free_payload_node(temp);
    temp = next;
  }
}
