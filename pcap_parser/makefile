CFLAGS += -lpcap -Wall -Wextra -Wpedantic \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

run: com
	./test.o
	# ./parse_online.o

com: 
	cppcheck .
	gcc  -g -o test.o test.c lib/dissection.c lib/hash_table.c lib/parsers.c lib/linked_list.c lib/handler.c $(CFLAGS)
	# gcc -g -o parse_offline.o  parse_offline.c lib/dissection.c lib/hash_table.c lib/parsers.c lib/linked_list.c -lpcap -Wall -Wextra
	# gcc -g -o parse_online.o  parse_online.c lib/dissection.c lib/hash_table.c lib/parsers.c lib/linked_list.c -lpcap -Wall -Wextra

clean:
	rm -f test.o parse_offline.o parse_online.o out.txt
