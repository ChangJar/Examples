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

char choice;                        /* option entered in commandline */
int padCounter = 0;                 /* number of padded bytes */

/*
 * Makes a cyptographically secure key by stretching a user entered key
 */
int GenerateKey(RNG* rng, byte* key, char* sz, byte* salt)
{
    int size = atoi(sz);
    int ret;

    ret = RNG_GenerateBlock(rng, salt, sizeof(salt)-1);
    if (ret != 0)
        return -1020;

    if (padCounter == 0)        /* sets first value of salt to check if the */
        salt[0] = 0;            /* message is padded */

    /* stretches key */
    ret = PBKDF2(key, key, strlen(key), salt, sizeof(salt), 4096, size, MD5);
    if (ret != 0)
        return -1030;

    return 0;
}

/*
 * Encrypts/Decrypts a file using Camellia 
 */
int CamelliaTest(char* fileIn, char* fileOut, byte* key, char* size)
{
    FILE*    inFile =  fopen(fileIn, "r");/* file used to take message from */
    FILE*    outFile = fopen(fileOut, "w");/* file made to wrtie message to */

    Camellia cam;                       /* camellia for encoding/decoding */
    RNG      rng;                            /* random number generator */

    /* Initialization vector: used for randomness of encryption */
    byte    iv[CAMELLIA_BLOCK_SIZE];    /* should be random or pseudorandom */
    byte*   input;                      /* array for inFile info */
    byte*   output;                     /* array for outFile info */ 
    byte    salt[8] = {0};              /* salt used for decryption purposes */

    int     i = 0;                      /* loop counter */
    int     ret = 0;                    /* return variable for errors */
    long    numBlocks = 0;              /* number of ASE blocks for encoding */
    int     inputLength;                /* length of message */
    int     length;                     /* length of input after padding */

    /* finds the end of inFile to determine length */
    fseek(inFile, 0, SEEK_END);
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    
    /* pads the length until it evenly matches a block / increases pad number*/
    length = inputLength;    
    if (choice == 'e') {
        while(length % CAMELLIA_BLOCK_SIZE != 0) {
            length++;
            padCounter++;
        }
    }

    input = malloc(length);         /* sets size of input */

    /* reads from inFile and writes whatever is there to the input array */
    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = padCounter;
    } 
    /* finds the number of encoding blocks to be used */
    numBlocks = length / CAMELLIA_BLOCK_SIZE;

    output = malloc(CAMELLIA_BLOCK_SIZE * numBlocks); /* sets size of output */

    InitRng(&rng);                    /* initializes random number generator */

    if (choice == 'e') {
        /* if encryption was the chosen option */
        /* randomly generates iv */
        ret = RNG_GenerateBlock(&rng, iv, CAMELLIA_BLOCK_SIZE);
        if (ret != 0) 
            return -1020;

        /* stretches key to fit size */
        ret = GenerateKey(&rng, key, size, salt);
        if (ret != 0)
            return -1040;

        /* sets key */
        ret = CamelliaSetKey(&cam, key, CAMELLIA_BLOCK_SIZE, iv);
        if (ret != 0)
            return -1001;

        /* encrypts the message to the ouput based on input length + padding */
        CamelliaCbcEncrypt(&cam, output, input, length);
        if (ret != 0)
            return -1005;

        /* writes to outFile */
        fwrite(salt, 1, sizeof(salt), outFile);
        fwrite(iv, 1, CAMELLIA_BLOCK_SIZE, outFile);
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

        /* replicates old key if entered keys match*/
        ret = PBKDF2(key, key, strlen(key), salt, sizeof(salt), 4096, 
            atoi(size), MD5);
        if (ret != 0)
            return -1030;

        /* sets key */
        ret = CamelliaSetKey(&cam, key, CAMELLIA_BLOCK_SIZE, iv);
        if (ret != 0)
            return -1001;

        /* change length to remove iv block from being decrypted */
        length -= (CAMELLIA_BLOCK_SIZE + sizeof(salt));
        for (i = 0; i < length; i++) {
            /* shifts message over an encryption block: ignores iv on message*/
            input[i] = input[i + (CAMELLIA_BLOCK_SIZE + sizeof(salt))];
        }
        /* decrypts the message to output based on input */
        CamelliaCbcDecrypt(&cam, output, input, length);

        if (salt[0] != 0) {
            /* reduces length based on number of padded elements */
            length -= output[length-1];
        }
        /* writes output to the outFile based on shortened length */
        fwrite(output, 1, length, outFile);
    }
    /* closes the opened files and frees the memory*/
    free(input);
    free(output);
    free(key);
    fclose(inFile);
    fclose(outFile);

    return 0;
}

/*
 * help message
 */
void help()
{
    printf("\n~~~~~~~~~~~~~~~~~~~~|Help|~~~~~~~~~~~~~~~~~~~~~\n\n");
    printf("Usage: ./camellia-encrypt <-option> <KeySize> <file.in> "
        "<file.out>\n\n");
    printf("Options\n");
    printf("-d    Decryption\n-e    Encryption\n-h    Help\n");
}

/*
 * temporarily deisables echoing in terminal for secure key input
 */
int NoEcho(char* key, char* size)
{
    struct termios oflags, nflags;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error\n");
        return -1060;
    }

    printf("Key: ");
    fgets(key, atoi(size), stdin);
    key[strlen(key) - 1] = 0;

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error\n");
        return -1070;
    }
}

int main(int argc, char** argv)
{
    int    option;    /* choice of how to run program */
    byte*  key;       /* user entered key */
    int    ret = 0;   /* return value */

    if (argc != 5) {
        /* if number of arguments is not 5 'help' */
        help();
    } 
    else if (atoi(argv[2]) != 128 && atoi(argv[2]) != 192 && 
        atoi(argv[2]) != 256) {
        /* if the entered size does not match acceptable size */
        printf("Invalid Camellia key size\n");
        ret = -1080;
    }
    else {
        key = malloc(atoi(argv[2]));    /* sets size memory of key */
        ret = NoEcho((char*)key, argv[2]);
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
        ret = CamelliaTest(argv[3], argv[4], key, argv[2]);
    }
    
    return ret;
}
