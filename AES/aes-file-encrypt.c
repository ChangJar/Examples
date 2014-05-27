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

int aes_test(char* fileIn, char* fileOut, byte* key)
{
    FILE* input =   fopen(fileIn, "r");
    FILE* output =  fopen(fileOut, "w");

    Aes enc;
    Aes dec;
    
    fseek(input, 0, SEEK_END);
    long length = ftell(input);
    byte msg[length];
    fseek(input, 0, SEEK_SET);
    fread(msg, 1, length, input);

    byte iv[]  = "1234567890abcdef   ";
    
    byte cipher[AES_BLOCK_SIZE * 4];
    byte plain [AES_BLOCK_SIZE * 4];
    int ret;
   
    ret = AesSetIV(&enc, iv);
    if (ret != 0)
        return -9001;
    ret = AesSetIV(&dec, iv);
    if (ret != 0)
        return -9002;

    ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1001;
    ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1002;

    ret = AesCbcEncrypt(&enc, cipher, msg, length);//AES_BLOCK_SIZE * 2);
    if (ret != 0)
        return -1005;
    ret = AesCbcDecrypt(&dec, plain, cipher, length);//AES_BLOCK_SIZE * 2);
    if (ret != 0)
        return -1006;
    
    ret = memcmp(plain, msg, AES_BLOCK_SIZE * 2);
    if (ret != 0)
        return -60;

    fwrite(plain, 1, length, output);
    fclose(input);
    fclose(output);
    return 0;
}

int main(int argc, char** argv)
{
    byte key[] = "0123456789abcdef   ";
    if (argc != 4 && argc != 3)
        printf("Usage: ./aes-file-encrypt <file.in> <file.out> <key(Optnl)>\n");
    else if (argc == 4) 
        strcpy(key, argv[3]);
   
    int err = aes_test(argv[1], argv[2], key);
    printf("%d\n", err);
    return 0;
}

