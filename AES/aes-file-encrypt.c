/*aes-file-encrypt.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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

char choice;                        /* option inputed in commandline */

int AesTest(char* fileIn, char* fileOut, byte* key)
{
    FILE* input =   fopen(fileIn, "r"); /* file used to take message from */
    FILE* output =  fopen(fileOut, "w");/*file used to write changed msg to  */

    Aes enc;                            /* AES for encoding */
    Aes dec;                            /* AES for decoding */

    /* Initialization vector: used for randomness of encryption */
    byte iv[]  = "onetwothreefour";     /* should be random or pseudorandom */   
    int ret;                            /* return variable for errors */
    int numBlocks;                      /* number of ASE blocks for encoding */
    
    /* finds the end of input to determine length */
    fseek(input, 0, SEEK_END);
    int msgLength = ftell(input);       /* length of message */
    fseek(input, 0, SEEK_SET);
    
    int length;                         /* length of msg after padding */
    
    length = msgLength;    
    /* increases the length until it evenly matches a block */
    while(length % AES_BLOCK_SIZE != 0) {
        length++;
    }

    byte msg[length];                   /* actuall message */

    /* reads from input and writes whatevers there to the msg array */
    fread(msg, 1, length, input);

    int i;                              /* loop counter */
    for (i = msgLength; i < length; i++) {
        /* padds the added characters with whitespace */
        msg[i] = 0x20;
    } 

    /* finds the number of encoding blocks to be used */
    numBlocks = length/AES_BLOCK_SIZE;
    /* printed out for error checking */
    printf("numBlocks: %d\n", numBlocks);

    byte cipher[AES_BLOCK_SIZE * numBlocks];/* encoded message[] */
    byte plain [AES_BLOCK_SIZE * numBlocks];/* decoded message[] */

    if (choice == 'e') {
        /* if encryption was the chosen option */
        /* set encryption key. must have key to decrypt */
        ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1001;

        /* encrypts the message to the cypher based on msg length+padding */
        ret = AesCbcEncrypt(&enc, cipher, msg, length);
        if (ret != 0)
            return -1005;

        /* writes cipher on output file */
        fwrite(cipher, 1, length, output);

    }
    if (choice == 'd') {
        /* if decryption was the chosen option */
        /* sets the key to use, if it matches the encryption key success */
        ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        if (ret != 0)
            return -1002;

        /* decrypts the message to plaintext based on msg length+padding */
        ret = AesCbcDecrypt(&dec, plain, msg, length);
        if (ret != 0)
            return -1006;
        
        /* writes plaintext to the ouput file */
        fwrite(plain, 1, length, output);
    }
    /* closes the open files */
    fclose(input);
    fclose(output);

    return 0;
}

int main(int argc, char** argv)
{
    byte key[] = "0123456789abcdef   "; /* default key (changed in cmd line) */
    int err;                            /* error variable */
    int option;                         /* option chosen in command line */
    
    /* if the argument count isn't 2, 4, or 5 */
    if (argc != 5 && argc != 4 && argc != 2)
        printf("Usage: ./aes-file-encrypt <-option> <file.in>"
                " <file.out> <key(Optional)>\n");
    /* if there are 5 arguments, the last one is the key */
    else if (argc == 5) 
        strcpy(key, argv[4]);   /* copies the argument to the key */
    /* if only two arguments are entered display 'help' becomes the choice */
    else if (argc == 2)
        choice = 'h';
    /* if 'help' is the choice */
    if (choice == 'h') {
        printf("\n~~~~~~~~~~~~~~~~~~~~Help~~~~~~~~~~~~~~~~~~~~~\n\n");
        printf("Usage: ./aes-file-encrypt <-option>  <file.in> <file.out>"
                " <key(Optional)>\n\n");
        printf("Options\n");
        printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
    }
    else {
        while ((option = getopt(argc, argv, "de:")) != -1) {
            switch (option) {
                case 'd':
                    choice = 'd';
                    break;
                case 'e':
                    choice = 'e';
                    break;
                default:
                    abort();
            }
        }
        err = AesTest(argv[2], argv[3], key);
        printf("%d\n", err);
    }
    return 0;
}

