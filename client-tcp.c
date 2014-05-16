#include    <stdio.h>               /* must include these libraries */
#include    <stdlib.h>                  
#include    <string.h>
#include    <errno.h>
#include    <arpa/inet.h>

#define SERV_PORT   11111   /* Define default port number */
#define MAXDATASIZE 4096    /* Maximum acceptable amount of data */

/* Command line argumentCount and argumentValues */
int main(int argc, char** argv) 
{
    int     sockfd;                             /* Socket File Discriptor */
    struct  sockaddr_in servAddr;               /* Struct for Server Address */
    char    send[] = "Initiating Contact...";   /* Data sent to server */
    char*   msg = send;                         /* Pointer for data */
    char    recieve[MAXDATASIZE];               /* Recived data from server*/

    /* if the number of arguments is not two, error */
    if(argc != 2) {
        printf("usage: ./client-tcp  <IP address>\n");
        exit(EXIT_FAILURE);
    }
    /* Internet Address Family, Stream based tcp, default protocol */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {                        /* If the socket fails */
        printf("Failed to create socket. errono: %i\n", errno);
        exit(EXIT_FAILURE);
    }

    bzero(&servAddr, sizeof(servAddr));     /* Clears memory block for use */
    servAddr.sin_family = AF_INET;          /* Sets AddressFamily to internet*/
    servAddr.sin_port = htons(SERV_PORT);   /* Sets port to defined port */

    /* Looks for the Server at the entered address (IP in the command line) */
    inet_pton(AF_INET, argv[1], &servAddr.sin_addr);

    /* If socket fails to connect to the server*/
    if(connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        printf("Connect error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("%s\n",msg);
    /* If the message is not able to send */
    if(write(sockfd, msg, strlen(msg)) != strlen(msg)) {
        printf("Writte error: errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    /* If the server fails to return data */
    if(read(sockfd, recieve, MAXDATASIZE) == 0) {
        printf("Read error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("Recieved: %s\n",recieve); /* Print data recieved from the server */
    return 0;
} 
