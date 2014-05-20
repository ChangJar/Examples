/* client-tcp.c
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

#define MAXDATASIZE  4096   /* maximum acceptable amount of data */
#define SERV_PORT    11111  /* define default port number */

/* 
 * clients initial contact with server. (socket to connect, security layer)
 */
void ClientGreet(int sock, CYASSL* ssl)
{
    /* data to send to the server, data recieved from the server */
    char send[MAXDATASIZE], receive[MAXDATASIZE];

    printf("Message for server:\t");
    fgets(send, MAXDATASIZE, stdin);

    if (CyaSSL_write(ssl, send, strlen(send)) != strlen(send)) {
        /* the message is not able to send, or error trying */
        printf("Write error: errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }

    if (CyaSSL_read(ssl, receive, MAXDATASIZE) == 0) {
        /* the server failed to send data, or error trying */
        printf("Read error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("Recieved: \t%s\n", receive);
}
/* 
 * applies TLS 1.2 security layer to data being sent.
 */
void Security(int sock)
{
    CyaSSL_Init();      /* initialize CyaSSL (must be done first) */
    CYASSL_CTX* ctx;
    CYASSL*     ssl;    /* create CYASSL object */

    /* create and initiLize CYASSL_CTX structure */
    if ((ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method())) == NULL) {
        printf("SSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    /* load CA certificates into CyaSSL_CTX. which will verify the server */
    if (CyaSSL_CTX_load_verify_locations(ctx, "./ca-cert.pem",0) != 
            SSL_SUCCESS) {
        printf("Error loading ./certs/ca-cert.pem. Please check the file.\n");
        exit(EXIT_FAILURE);
    }
    if ((ssl = CyaSSL_new(ctx)) == NULL) {
        printf("CyaSSL_new error.\n");
        exit(EXIT_FAILURE);
    }
    CyaSSL_set_fd(ssl, sock);
    ClientGreet(sock, ssl);

    /* frees all data before client termination */
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
}
/* 
 * Command line argumentCount and argumentValues 
 */
int main(int argc, char** argv) 
{
    int     sockfd;                             /* socket file discriptor */
    struct  sockaddr_in servAddr;               /* struct for server address */

    if (argc != 2) {
        /* if the number of arguments is not two, error */
        printf("usage: ./client-tcp  <IP address>\n");
        exit(EXIT_FAILURE);
    }

    /* internet address family, stream based tcp, default protocol */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        printf("Failed to create socket. errono: %i\n", errno);
        exit(EXIT_FAILURE);
    }

    /* clears memory block for use */
    bzero(&servAddr, sizeof(servAddr));    
    /* sets addressfamily to internet*/
    servAddr.sin_family = AF_INET;         
    /* sets port to defined port */
    servAddr.sin_port = htons(SERV_PORT);  

    /* looks for the server at the entered address (ip in the command line) */
    inet_pton(AF_INET, argv[1], &servAddr.sin_addr);

    if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        /* if socket fails to connect to the server*/
        printf("Connect error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    Security(sockfd);
    return 0;
}

