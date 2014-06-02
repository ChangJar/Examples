/* aes-file-encrypt.c
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

#include    <stdio.h>
#include    <cyassl/ctaocrypt/aes.h>

char choice;                            /* option entered in commandline */

int AesTest(char* fileIn, char* fileOut, byte* key)
{
    FILE* inFile =  fopen(fileIn, "r"); /* file used to take message from */
    FILE* outFile = fopen(fileOut, "w");/* file used to write message to */

    Aes enc;                            /* AES for encoding */
    Aes dec;                            /* AES for decoding */

    /* Initialization vector: used for randomness of encryption */
    byte iv[] = "onetwothreefour"; 		/* should be random or pseudorandom */
    int ret;                            /* return variable for errors */
    long numBlocks;                     /* number of ASE blocks for encoding */
    int padCounter = 0;                 /* number of padded bytes */

    /* finds the end of inFile to determine length */
    fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);       /* length of message */
    fseek(inFile, 0, SEEK_SET);
    int length;                         /* length of input after padding */
    
    length = inputLength;    
    /* pads the length until it evenly matches a block / increases pad number*/
    while(length % AES_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    byte input[length];                   /* actual message */

    /* reads from inFile and writes whatever is there to the input array */
    fread(input, 1, length, inFile);

    int i;                              /* loop counter */
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with the number of pads */
        input[i] = 0%padCounter;
    } 
    /* finds the number of encoding blocks to be used */
    numBlocks = length/AES_BLOCK_SIZE;

    byte output[AES_BLOCK_SIZE * numBlocks];/* outFile message[] */

    if (choice == 'e') {
        /* if encryption was the chosen option 
        set encryption key. must have key to decrypt */
        ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1001;

        /* encrypts the message to the ouput based on input length + padding */
        ret = AesCbcEncrypt(&enc, output, input, length);
        if (ret != 0)
            return -1005;

        /* writes output to outFile */
        fwrite(output, 1, length, outFile);
    }
    if (choice == 'd') {
        /* if decryption was the chosen option
        sets the key to use, if it matches the encryption key success */
        ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        if (ret != 0)
            return -1002;

        /* decrypts the message to output based on input length + padding */
        ret = AesCbcDecrypt(&dec, output, input, length);
        if (ret != 0)
            return -1006;

        int i;                              /* loop counter */
        /* checks the last block for padding */
        for (i = AES_BLOCK_SIZE * (numBlocks - 1); i < length; i++) {
            if(output[i] == output[length-1])
                inputLength--;
        }

        /* writes output to the outFile based on shortened length */
        fwrite(output, 1, inputLength, outFile);
    }
    /* closes the opened files */
    fclose(inFile);
    fclose(outFile);

    return 0;
}
 void help()
 {
    printf("\n~~~~~~~~~~~~~~~~~~~~|Help|~~~~~~~~~~~~~~~~~~~~~\n\n");
        printf("Usage: ./aes-file-encrypt <-option> <file.in> <file.out>"
                " <key>\n\n");
        printf("Options\n");
        printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
 }
 int main(int argc, char** argv)
 {
    int option;

    if (argc != 5) /* if number of arguments is not 5 'help' */
        help();
    else {
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
        AesTest(argv[2], argv[3], argv[4]);
    }
    return 0;
 }
