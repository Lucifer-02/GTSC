run: com
	./test.o
	# ./parse_online.o

com: 
	cppcheck .
	gcc -o test.o test.c lib/dissection.c lib/hash_table.c lib/parsers.c  -lpcap -Wall -Wextra
	# gcc -o parse_offline.o  parse_offline.c lib/dissection.c lib/hash_table.c -lpcap -Wall -Wextra
	# gcc -o parse_online.o  parse_online.c lib/dissection.c lib/hash_table.c -lpcap -Wall -Wextra

clean:
	rm -f test.o parse_offline.o parse_online.o out.txt
