CC=gcc

camellia-encrypt: camellia-encrypt.c
	$(CC) -Wall -o camellia-encrypt camellia-encrypt.c -lcyassl 

.PHONY: clean

clean:
	find . \! -name camellia-encrypt.c \! -name Makefile \! -name README -delete
