#ifndef HANDLER_H
#define HANDLER_H

#include "flow_api.h"
#include "hash_table.h"
#include "parsers.h"

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt);
void print_hashtable(HashTable const table);
void print_flows(Node const *const head);

// print all payloads in a flow
void print_flow(flow_base_t flow);

// print all payloads in a flow direction
void print_flow_direction(Node const *head, bool is_up);
Node *create_flow_node(uint64_t key, flow_base_t flow);
Node *create_payload_node(parsed_packet pkt);

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt);

// get flow direction by compare src ip of the packet with the flow
Node **get_flow_direction(flow_base_t const *flow, parsed_packet pkt);

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt);

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt);

void print_payload(u_char const *payload, uint payload_size);
void print_hex_ascii_line(u_char const *const payload, int len, int offset);

// check packet is up or down
bool is_up(flow_base_t const *flow, parsed_packet pkt);

void insert_tcp_direction(uint32_t pkt_seq, uint32_t *exp_seq, Node **direction,
                          parsed_packet pkt);
#endif
