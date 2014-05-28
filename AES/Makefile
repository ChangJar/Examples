CC=gcc

aes-file-encrypt: aes-file-encrypt.c
	$(CC) -o aes-file-encrypt aes-file-encrypt.c -lcyassl

.PHONY: clean

clean:
	find . \! -name aes-file-encrypt.c \! -name Makefile -delete
