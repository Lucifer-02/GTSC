#ifndef HANDLER_H
#define HANDLER_H

#include "hash_table.h"
#include "parsers.h"

// classify and insert a new packet into hash table
void prepare_insert(HashTable table, struct parsed_packet pkt);

#endif
