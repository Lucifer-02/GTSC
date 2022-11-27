run: com
	./main.o

com: 
	# clang -o main main.c map.c -Wall -Wextra -g
	clang -o main.o main.c -Wall -Wextra -g
	cppcheck main.c

clean:
	rm -f main.o
