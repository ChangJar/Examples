/* camellia-encrypt.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <cyassl/options.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/camellia.h>

char choice;

void GenerateKey(byte* key, char* sz, byte* salt)
{
    RNG rng;
    int size = atoi(sz);

    RNG_GenerateBlock(&rng, salt, 8);
    PBKDF2(key, key, sizeof(key), salt, 8, 4096, size, MD5);
}
int CamelliaTest(char* fileIn, char* fileOut, byte* key, char* size)
{
    FILE* inFile =  fopen(fileIn, "ra");/* file used to take message from */
    FILE* outFile = fopen(fileOut, "wa");/* file made to wrtie message to */

    Camellia cam;                       /* camellia for encoding/decoding */
    RNG rng;                            /* random number generator */

    /* Initialization vector: used for randomness of encryption */
    byte iv[CAMELLIA_BLOCK_SIZE];       /* should be random or pseudorandom */
    int i = 0;                          /* loop counter */
    int ret = 0;                        /* return variable for errors */
    long numBlocks = 0;                 /* number of ASE blocks for encoding */
    int padCounter = 0;                 /* number of padded bytes */

    /* finds the end of inFile to determine length */
    fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);    /* length of message */
    fseek(inFile, 0, SEEK_SET);
    int length;                         /* length of input after padding */
    
    length = inputLength;    
    /* pads the length until it evenly matches a block / increases pad number*/
    while(length % CAMELLIA_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    byte input[length];                 /* actual message */
    byte salt[8];

    /* reads from inFile and writes whatever is there to the input array */
    fread(input, 1, inputLength, inFile);
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = padCounter;
    } 
    /* finds the number of encoding blocks to be used */
    numBlocks = length / CAMELLIA_BLOCK_SIZE;

    byte output[CAMELLIA_BLOCK_SIZE * numBlocks];/* outFile message[] */

    if (choice == 'e') {
        /* if encryption was the chosen option */
        /* randomly generates iv */
        RNG_GenerateBlock(&rng, iv, CAMELLIA_BLOCK_SIZE);
        /* sets new randomized iv */
        CamelliaSetIV(&cam, iv);
        /* stretches key to fit size */
        GenerateKey(key, size, salt);
        /* sets key */
        CamelliaSetKey(&cam, key, CAMELLIA_BLOCK_SIZE, iv);
        /* encrypts the message to the ouput based on input length + padding */
        CamelliaCbcEncrypt(&cam, output, input, length);
        /* writes salt to outFile */
        fwrite(salt, 1, sizeof(salt), outFile);
        /* writes iv to outFile */
        fwrite(iv, 1, CAMELLIA_BLOCK_SIZE, outFile);
        /* writes output to outFile */
        fwrite(output, 1, length, outFile);
    }
    if (choice == 'd') {
        /* if decryption was the chosen option */
        for (i = 0; i < sizeof(salt); i++) {
            /* finds salt from input message */
            salt[i] = input[i];
        }
        for (i = sizeof(salt); i < CAMELLIA_BLOCK_SIZE + sizeof(salt); i++) {
            /* finds iv from input message */
            iv[i - sizeof(salt)] = input[i];
        }
        /* sets iv to found iv */
        CamelliaSetIV(&cam, iv);
        /* replicates old key */
        PBKDF2(key, key, sizeof(key), salt, sizeof(salt), 4096, atoi(size),
            MD5);
        /* sets key */
        CamelliaSetKey(&cam, key, CAMELLIA_BLOCK_SIZE, iv);

        /* change length to remove iv block from being decrypted */
        length-=(CAMELLIA_BLOCK_SIZE + sizeof(salt));
        for (i = 0; i < length; i++) {
            /* shifts message over an encryption block: ignores iv on message*/
            input[i] = input[i + (CAMELLIA_BLOCK_SIZE + sizeof(salt))];
        }
        /* decrypts the message to output based on input */
        CamelliaCbcDecrypt(&cam, output, input, length);

        /* reduces length based on salt size */
        length -= sizeof(salt);
        /* reduces length based on number of padded elements */
        length -= output[length-1];

        /* writes output to the outFile based on shortened length */
        fwrite(output, 1, length, outFile);
    }
    /* closes the opened files */
    fclose(inFile);
    fclose(outFile);

    return 0;
}
void help()
{
    printf("\n~~~~~~~~~~~~~~~~~~~~|Help|~~~~~~~~~~~~~~~~~~~~~\n\n");
    printf("Usage: ./camellia-encrypt <-option> <KeySize> <file.in> "
        "<file.out>\n\n");
    printf("Options\n");
    printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
}
void NoEcho(char* key)
{
    struct termios oflags, nflags;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error\n");
    }

    printf("Key: ");
    fgets(key, sizeof(key), stdin);
    key[strlen(key) - 1] = 0;

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error\n");
    }
}
int main(int argc, char** argv)
{
    int option = 0;
    byte key[64];

    if (argc != 5) /* if number of arguments is not 5 'help' */
        help();
    else {
        NoEcho((char*)key);
        while ((option = getopt(argc, argv, "deh:")) != -1) {
            switch (option) {
                case 'd': /* if entered decrypt */
                    choice = 'd';
                    break;
                case 'e': /* if entered encrypt */
                    choice = 'e';
                    break;
                case 'h': /* if entered 'help' */
                    help();
                    break;
                default:
                    abort();
            }
        }
        CamelliaTest(argv[3], argv[4], key, argv[2]);
    }
    return 0;
}
