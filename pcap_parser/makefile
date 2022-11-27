run: com
	./test.o

com: 
	gcc -o test.o test.c lib/dissection.c lib/hash_table.c  -lpcap -Wall -Wextra 
	# clang -o parse_offline.o lib/dissection.c parse_offline.c -lpcap -Wall -Wextra
	# clang -o parse_online parse_online.c -lpcap -Wall -Wextra

clean:
	rm -f test.o parse_offline.o parse_online.o out.txt
