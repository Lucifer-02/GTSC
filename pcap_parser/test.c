#include "lib/dissection.h"
#include "lib/flow_api.h"
#include "lib/hash_table.h"
#include "lib/linked_list.h"
#include "lib/parsers.h"
#include <stdio.h>

const int HASH_TABLE_SIZE = 50;


int main() {

	// create hash table
	HashTable table = create_hash_table(HASH_TABLE_SIZE);

	print_hashtable(table);

	free_hash_table(table);
}

