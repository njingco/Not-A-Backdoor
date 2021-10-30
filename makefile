CC=gcc -Wall -g
CLIB = -lpthread -lrt
SSL = -lssl -lcrypto

all: not_a_backdoor 

not_a_backdoor: not_a_backdoor.o crypto.o
	$(CC) -o not_a_backdoor not_a_backdoor.o crypto.o $(SSL)

clean:
	rm -f *.o not_a_backdoor crypto
	
not_a_backdoor.o:
	$(CC) -c not_a_backdoor.c $(SSL)

crypto.o:
	$(CC) -c crypto.c $(SSL)


