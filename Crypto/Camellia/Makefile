CC=gcc

camellia-encrypt: camellia-encrypt.c
	$(CC) -o camellia-encrypt camellia-encrypt.c -lcyassl 

.PHONY: clean

clean:
	find . \! -name camellia-encrypt.c \! -name Makefile \! -name README -delete
