CC=gcc

client-tls: client-tls.c
	$(CC) -o client-tls client-tls.c -lcyassl

.PHONY: clean

clean:
	rm -f client-tls
