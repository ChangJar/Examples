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

 #include <stdio.h>
 #include <cyassl/ctaocrypt/des3.h>

 int Des3Test(char* fileIn, char* fileOut, byte* key, char choice)
 {
 	FILE* input =	fopen(fileIn, "r");
 	FILE* output =	fopen(fileOut, "w");

 	Des3 enc;
 	Des3 dec;

 	int ret;
 	int numBlocks;

 	fseek(input, 0, SEEK_END);
    int msgLength = ftell(input);
    fseek(input, 0, SEEK_SET);
    byte msg[msgLength];

 	byte plain[msgLength];
 	byte cipher[msgLength];

 	const byte iv[] = {
 		0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
 		0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
 		0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
 	};

 	fread(msg, 1, msgLength, input);

 	ret = Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
	if (ret != 0)
		return -100;

	ret = Des3_SetKey(&dec, key, iv, DES_DECRYPTION);
 	if (ret != 0)
 			return -101;

 	if (choice == 'e')
 	{
 		ret = Des3_CbcEncrypt(&enc, cipher, msg, msgLength);
 		if (ret != 0)
 			return -200;

 		fwrite(cipher, 1, msgLength, output);
 	}
 	if (choice == 'd')
 	{
 		ret = Des3_CbcDecrypt(&dec, plain, msg, msgLength);
 		if (ret != 0)
 			return -201;

 		fwrite(plain, 1, msgLength, output);
 	}

 	fclose(output);
 	fclose(input);
 	return 0;
 }
 void help()
 {
 	printf("\n~~~~~~~~~~~~~~~~~~~~Help~~~~~~~~~~~~~~~~~~~~~\n\n");
        printf("Usage: ./aes-file-encrypt <-option> <file.in> <file.out>"
                " <key>\n\n");
        printf("Options\n");
        printf("-d    Decpription\n-e    Encryption\n-h    Help\n");
 }
 int main(int argc, char** argv)
 {
 	char choice;
 	int err;
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
        err = Des3Test(argv[2], argv[3], argv[4], choice);
        printf("%d\n", err);
    }
 	return 0;
 }