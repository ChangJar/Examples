#include    <stdio.h>               /* must include these libraries */
#include    <stdlib.h>                  
#include    <string.h>
#include    <errno.h>
#include    <arpa/inet.h>
#include    <cyassl/ssl.h>          /* CyaSSL security library */

#define MAXDATASIZE  4096   /* Maximum acceptable amount of data */
#define SERV_PORT    11111  /* Define default port number */

void clientHello(int sock, CYASSL* ssl)
{
    char send[MAXDATASIZE], recieve[MAXDATASIZE];   /*Data sent, data revieved*/

    printf("Message for server:\t");
    fgets(send,MAXDATASIZE,stdin);
    /* If the message is not able to send */
    if(CyaSSL_write(ssl, msg, strlen(msg)) != strlen(msg)) {
        printf("Writte error: errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    /* If the server fails to send data */
    if(CyaSSL_read(ssl, recieve, MAXDATASIZE) == 0) {
        printf("Read error. errno: %i\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("Recieved: \t%s\n", recieve); /* Print data sent from the server */
}
void security(int sock)
{
    CyaSSL_Init();      /* Initialize CyaSSL */
    CYASSL_CTX* ctx;
    CYASSL*     ssl;    /* Creat CYASSL object */

    /* Create and initiLize CYASSL_CTX structure */
    if((ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method())) == NULL) {
        printf("SSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }
    /* Load CA certificates into CYASSL CTX. which will verify the server */
    if(CyaSSL_CTX_load_verify_locations(ctx,"./certs/ca-cert.pem",0) != 
            SSL_SUCCESS) {
        printf("Error loading ./certs/ca-cert.pem. Please check the file.\n");
        exit(EXIT_FAILURE);
    }
    if((ssl = CyaSSL_new(ctx)) == NULL) {
        printf("CyaSSL_new error.\n");
        exit(EXIT_FAILURE);
    }
    CyaSSL_set_fd(ssl, sock);

    clientHello(sock, ssl);
    
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
}
/* Command line argumentCount and argumentValues */
int main(int argc, char** argv) 
{
    int     sockfd;                             /* Socket File Discriptor */
    struct  sockaddr_in servAddr;               /* Struct for Server Address */
   
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
    security(sockfd);
    return 0;
}
