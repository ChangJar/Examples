CC=gcc

client-tcp: client-tcp.c
	$(CC) -o client-tcp client-tcp.c -I.

.PHONY: clean

clean:
	rm -f client-tcp
