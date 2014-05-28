/* client-tls.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include    <stdio.h>
#include    <stdlib.h>                  
#include    <string.h>
#include    <errno.h>
#include    <arpa/inet.h>
#include    <cyassl/ssl.h>          /* cyaSSL security library */
#include    <cyassl/ctaocrypt/aes.h>

char choice;

int aes_test(char* fileIn, char* fileOut, byte* key)
{
    FILE* input =   fopen(fileIn, "r");
    FILE* output =  fopen(fileOut, "w");

    Aes enc;
    Aes dec;

    byte iv[]  = "1234567890abcdef   ";

    int ret;

    int numBlocks;
    int msgLength;
    fseek(input, 0, SEEK_END);
    int length = ftell(input);
    fseek(input, 0, SEEK_SET);

    msgLength = length;
    while(length % AES_BLOCK_SIZE != 0) {
        length++;
    }

    byte msg[length];

    fread(msg, 1, length, input);
    int i;
    for (i = msgLength; i < length; i++) {
        msg[i] = 0x20;
    } 

    numBlocks = length/AES_BLOCK_SIZE;
    printf("numBlocks: %d\n", numBlocks);

    byte cipher[AES_BLOCK_SIZE * numBlocks];
    byte plain [AES_BLOCK_SIZE * numBlocks];

    if (choice == 'e') {
        ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1001;

        ret = AesCbcEncrypt(&enc, cipher, msg, length);
        if (ret != 0)
            return -1005;

        fwrite(cipher, 1, length, output);

    }
    if (choice == 'd') {
        ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        if (ret != 0)
            return -1002;


        ret = AesCbcDecrypt(&dec, plain, msg, length);
        if (ret != 0)
            return -1006;

        fwrite(plain, 1, length, output);
    }

    fclose(input);
    fclose(output);

    return 0;
}

int main(int argc, char** argv)
{
    byte key[] = "0123456789abcdef   "; 
    int err;
    int option;

    if (argc != 5 && argc != 4 && argc != 2)
        printf("Usage: ./aes-file-encrypt <file.in>"
                " <file.out> <key(Optional)> <-option>\n");
    else if (argc == 5) 
        strcpy(key, argv[3]);
    else if (argc == 2)
        choice = 'h';
    if (choice == 'h') {
        printf("\n~~~~~~~~~~~~~~~~~~~~Help~~~~~~~~~~~~~~~~~~~~~\n\n");
        printf("Usage: ./aes-file-encrypt <file.in> <file.out>"
                " <key(Optional)> <-option>\n\n");
        printf("Options\n");
        printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
    }
    else {
        while ((option = getopt(argc, argv, "deh:")) != -1) {
            switch (option) {
                case 'd':
                    choice = 'd';
                    break;
                case 'e':
                    choice = 'e';
                    break;
                case 'h':
                    choice = 'h';
                    break;
                default:
                    abort();
            }
        }
        err = aes_test(argv[2], argv[3], key);
        printf("%d\n", err);
    }
    return 0;
}

