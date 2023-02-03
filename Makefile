CC = gcc

all: deauth-attack
	
deauth-attack: main.o 
	gcc -o deauth-attack main.o -lpcap 
main.o: main.c 
	gcc -c -o main.o main.c
clean:
	rm -f *.o deauth-attack