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

#define MAXDATASIZE  4096   /* maximum acceptable amount of data */
#define SERV_PORT    11111  /* define default port number */

/*
 *  clients initial contact with server. Socket to connect to: sock
 */
void ClientGreet(int sock)
{
    /* data to send to the server, data recieved from the server */
    char send[MAXDATASIZE], recieve[MAXDATASIZE];

    printf("Message for server:\t");
    fgets(send, MAXDATASIZE, stdin);

    if (write(sock, send, strlen(send)) != strlen(send)) {
        /* the message is not able to send, or error trying */
        printf("Write error: errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }

    if (read(sock, recieve, MAXDATASIZE) == 0) {
        /* the server fails to send data, or error trying */
        printf("Read error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Recieved: \t%s\n", recieve);
}

/* 
 * command line argumentCount and argumentValues 
 */
int main(int argc, char** argv) 
{
    int     sockfd;                             /* socket file discriptor */
    struct  sockaddr_in servAddr;               /* Struct for Server Address */

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
        printf("Connect error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    ClientGreet(sockfd);
    return 0;
}
