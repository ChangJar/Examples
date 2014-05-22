CC=gcc

client-tls-nonblocking: client-tls-nonblocking.c
	$(CC) -o client-tls-nonblocking client-tls-nonblocking.c -lcyassl

.PHONY: clean

clean:
	rm -f client-tls-nonblocking
