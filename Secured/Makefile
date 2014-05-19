CC=gcc

client-tcp: client-tls.c
	$(CC) -o client-tls client-tls.c -I -lm -lcyassl

.PHONY: clean

clean:
	rm -f client-tls
