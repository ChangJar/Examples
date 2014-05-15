#include    <stdio.h>               /* useful libraries to be included */
#include    <stdlib.h>                  
#include    <sys/socket.h>
#include    <netinet/in.h>
#include    <string.h>
#include    <unistd.h>
#include    <errno.h>
#include    <arpa/inet.h>
#include    <signal.h>

/* Define default port number */
#define SERV_PORT   1337

int Socket(int, int, int);
void Client(FILE *filePtr, int socket)
{
    
}
/* number of command line arguments, the arguments themselves */
int main(int argc, char** argv) 
{
    int     socket;
    struct  sockAddr_in servAddr;

    /* if the number of arguments is not two, error */
    if(argc != 2) {
        printf("usage: ./client-tcp  <IP address>\n");
        exit(EXIT_FAILURE);
    }
    socket = Socket(AF_INET, SOCK_STREAM, 0);

    return 0;
} 
