/* 3des-file-encrypt.c
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
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/pwdbased.h>

#define DES3_BLOCK_SIZE 24               /* size of encryption blocks */

char choice;                             /* option entered in commandline */

int GenerateKey(byte* key, char* sz, byte* salt)
{
    RNG rng;
    int size = atoi(sz);
    int ret;

    ret = RNG_GenerateBlock(&rng, salt, sizeof(salt));
    if (ret != 0) {
        printf("Could not Randomly Generate Block\n");
        return -1020;
    }
    ret = PBKDF2(key, key, strlen(key), salt, sizeof(salt), 4096, size, MD5);
    if (ret != 0) {
        printf("Could not stretch key\n");
        return -1030;
    }
    return 0;
}
int Des3Test(char* fileIn, char* fileOut, byte* key, char* size)
{
	FILE* inFile =	fopen(fileIn, "r"); /* file used to take message from */
	FILE* outFile =	fopen(fileOut, "w");/* file made to write messge to */

	Des3 enc;                           /* 3DES for encoding */
	Des3 dec;                           /* 3DES for decoding */
    RNG rng;

    /* Initialization vector: used for randomness of encryption */
    byte iv[DES3_BLOCK_SIZE];           /* should be random or pseudorandom */
    int i;                              /* loop counter */
	int ret;                            /* return variable for errors */
    long numBlocks;                     /* number of encryption blocks */
	int padCounter = 0;                 /* number of padded bytes */

    /* finds the end of inFile to determine length  */
	fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);    /* length of message */
    fseek(inFile, 0, SEEK_SET);
    int length;                         /* length of input after padding */

    length = inputLength;
    /* pads the length until it evenly matches a block / increases pad number*/
    while (length % DES3_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    byte input[length];                 /* actual message */
    byte salt[8];

    /* reads from inFile and wrties whatever is there to the input array */
    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = padCounter;
    }
    /*  finds the number of encoding blocks to be used*/
    numBlocks = length / DES3_BLOCK_SIZE;

    byte output[DES3_BLOCK_SIZE * numBlocks];/* outFile message[] */
printf("%lu\n", strlen(key));

	if (choice == 'e') {
        /* if encryption was the chosen option
        set encryption key. must have key to decrypt */
        ret = RNG_GenerateBlock(&rng, iv, DES3_BLOCK_SIZE);
        if (ret != 0) {
            printf("Could not Randomly Generate Block\n");
            return -1020;
        }
        /* sets key */
        ret = GenerateKey(key, size, salt);
        if (ret != 0) {
            printf("Could not Generate Key\n");
            return -1040;
        }
printf("%lu\n", strlen(key));
        ret = Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
        if (ret != 0)
            return -1001;

        /* encrypts the message to the ouput based on input length + padding */
		ret = Des3_CbcEncrypt(&enc, output, input, length);
		if (ret != 0)
			return -1005;

        /* writes salt to outFile */
        fwrite(salt, 1, sizeof(salt), outFile);
        /* writes iv to outFile */
        fwrite(iv, 1, DES3_BLOCK_SIZE, outFile);
        /* writes output to outFile */
		fwrite(output, 1, length, outFile);
	}
	if (choice == 'd') {
        /* if decryption was the chosen option */
        for (i = 0; i < sizeof(salt); i++) {
            /* finds salt from input message */
            salt[i] = input[i];
        }
        for (i = sizeof(salt); i < DES3_BLOCK_SIZE + sizeof(salt); i++) {
            /* finds iv from input message */
            iv[i - sizeof(salt)] = input[i];
        }
        /* replicates old key if keys match */
        ret = PBKDF2(key, key, strlen(key), salt, sizeof(salt), 4096, 
            atoi(size), MD5);
        if (ret != 0) {
            printf("Could not stretch Key\n");
            return -1050;
        }
printf("%lu\n", strlen(key));
        /* sets key */
        ret = Des3_SetKey(&dec, key, iv, DES_DECRYPTION);
        if (ret != 0)
            return -1002;

        /* change length to remove iv block from being decrypted */
        length-=(DES3_BLOCK_SIZE + sizeof(salt));
        for (i = 0; i < length; i++) {
            /* shifts message over an encryption block: ignores iv on message*/
            input[i] = input[i + (DES3_BLOCK_SIZE + sizeof(salt))];
        }
        /* decrypts the message to output based on input length + padding*/
		ret = Des3_CbcDecrypt(&dec, output, input, length);
		if (ret != 0)
			return -1006;

        /* reduces length based on salt size */
        length -= sizeof(salt)*2;
        if (length % DES3_BLOCK_SIZE == 0) {
            /* reduces length based on number of padded elements */
            length -= output[length-1];
        }
printf("Length %d\n", length);

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
    printf("Usage: ./3des-file-encrypt <-option> <KeySize> <file.in> "
        "<file.out>\n\n");
    printf("Options\n");
    printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
}
int NoEcho(char* key)
{
    struct termios oflags, nflags;
    int ret = 0;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error\n");
        ret = -1060;
    }

    printf("Key: ");
    fgets(key, 64, stdin);
    key[strlen(key) - 1] = 0;

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        printf("Error\n");
        ret = -1070;
    }
    return ret;
}
int main(int argc, char** argv)
{
	int option;
    byte key[64];
    int ret = 0;

	if (argc != 5) /* if number of arguments is not 5 'help' */
        help();
    else {
        ret = NoEcho((char*)key);
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
        ret = Des3Test(argv[3], argv[4], key, argv[2]);
    }
	return ret;
}
