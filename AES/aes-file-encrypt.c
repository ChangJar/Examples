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

int aes_test(char* fileIn, char* fileOut, byte* keys)
{
    FILE* input =   fopen(fileIn, "r");
    FILE* output =  fopen(fileOut, "w");

    Aes enc;
    Aes dec;
    
    fseek(input, 0, SEEK_END);
    long len = ftell(input);
    byte msg[len];

    const byte verify[] = {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };

    byte key[] = {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    byte iv[]  = {
        0x96,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    
    byte cipher[AES_BLOCK_SIZE * 4];
    byte plain [AES_BLOCK_SIZE * 4];
    int ret;

    ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1001;
    ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1002;

    ret = AesCbcEncrypt(&enc, cipher, msg, AES_BLOCK_SIZE);
    if (ret != 0)
        return -1005;
    ret = AesCbcDecrypt(&dec, plain, cipher, AES_BLOCK_SIZE);
    if (ret != 0)
        return -1006;

    if (memcmp(plain, msg, AES_BLOCK_SIZE))
        return -60;

    if (memcmp(cipher, verify, AES_BLOCK_SIZE))
        return -61;

    fseek(input, 0, SEEK_SET);
    fread(msg, 1, len, input);
    fprintf(output, "%s", msg);
    fclose(input);
    fclose(output);
    return 0;
}

int main(int argc, char** argv)
{
    byte key[] = "0123456789abcdef   ";
    if (argc != 4 && argc != 3)
        printf("Error: v dvnn fvcked vp\n");
    else if (argc == 4) 
        strcpy(key, argv[3]);
   
    aes_test(argv[1], argv[2], key);
    return 0;
}

