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
#include <cyassl/ctaocrypt/des3.h>

#define DES3_BLOCK_SIZE 24

char choice;

int Des3Test(char* fileIn, char* fileOut, byte* key)
{
	FILE* inFile =	fopen(fileIn, "r");
	FILE* outFile =	fopen(fileOut, "w");

	Des3 enc;
	Des3 dec;

    byte iv[] = "onetwothreefour";
	int ret;
    long numBlocks;
	long padCounter = 0;

	fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    int length;

    length = inputLength;
    while (length % DES3_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    byte input[length];

    fread(input, 1, inputLength, inFile);

    int i;                              /* loop counter */
    for (i = inputLength; i < length; i++) {
        /* padds the added characters with NULL */
        input[i] = 0%padCounter;
    }
    numBlocks = length/DES3_BLOCK_SIZE;

    byte output[DES3_BLOCK_SIZE * numBlocks];

	if (choice == 'e')
	{
    ret = Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
    if (ret != 0)
        return -100;
		ret = Des3_CbcEncrypt(&enc, output, input, length);
		if (ret != 0)
			return -200;

		fwrite(output, 1, length, outFile);
	}
	if (choice == 'd')
	{
    ret = Des3_SetKey(&dec, key, iv, DES_DECRYPTION);
    if (ret != 0)
        return -101;
		ret = Des3_CbcDecrypt(&dec, output, input, length);
		if (ret != 0)
			return -201;
        int i;
        for (i = DES3_BLOCK_SIZE * (numBlocks - 1); i < length; i++) {
            if (output[i] == output[length-1])
                inputLength--;
        }
     	fwrite(output, 1, inputLength, outFile);
	}
	fclose(outFile);
	fclose(inFile);
	return 0;
}
void help()
{
	printf("\n~~~~~~~~~~~~~~~~~~~~|Help|~~~~~~~~~~~~~~~~~~~~~\n\n");
    printf("Usage: ./3des-file-encrypt <-option> <file.in> <file.out>"
            " <key>\n\n");
    printf("Options\n");
    printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
}
int main(int argc, char** argv)
{
	int option;

	if (argc != 5)
    help();
    /* if only two arguments are entered display 'help' becomes the choice */
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
                	help();
                	break;
                default:
                    abort();
            }
        }
        Des3Test(argv[2], argv[3], argv[4]);
    }
	return 0;
}
