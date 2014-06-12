CC=gcc

3des-file-encrypt: 3des-file-encrypt.c
	$(CC) -o 3des-file-encrypt 3des-file-encrypt.c -lcyassl

.PHONY: clean

clean:
	find . \! -name 3des-file-encrypt.c \! -name Makefile \! -name README -delete
