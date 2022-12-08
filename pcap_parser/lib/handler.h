#ifndef HANDLER_H
#define HANDLER_H

#include "flow_api.h"
#include "hash_table.h"
#include "linked_list.h"
#include "parsers.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// classify and insert a new packet into hash table
void prepare_insert(HashTable table, struct parsed_packet pkt);
void print_hashtable(const HashTable table);
void print_flows(const Node *head);
// print all packets in a flow
void print_flow(const flow_base_t flow);
// print payload direction
void print_payload_direction(Node *head, bool is_up);
HashTable create_hash_table(const size_t size);
Node *create_flow_node(const uint64_t key, const flow_base_t flow);
Node *create_payload_node(const struct parsed_packet pkt);
flow_base_t create_flow(const struct parsed_packet pkt);
Node **get_flow_direction(const flow_base_t *flow,
                          const struct parsed_packet pkt);
// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key,
                    struct parsed_packet pkt);
void insert_udp_pkt(HashTable table, uint64_t flow_key,
                    struct parsed_packet pkt);
#endif
