CC=clang

client-tls-nonblocking: client-tls-nonblocking.c
	$(CC) -Wall -o client-tls-nonblocking client-tls-nonblocking.c -lcyassl

.PHONY: clean

clean:
	rm -f client-tls-nonblocking
