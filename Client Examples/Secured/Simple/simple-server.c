#include <cyassl/options.h>
#include <cyassl/test.h>

int main(int argc, char** argv)
{
	int			ret, sockfd, clientfd;
	char		buff[80];
	const char 	reply[]  = "I hear ya fa shizzle!\n";
	CYASSL*		ssl;
	CYASSL_CTX*	ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());

	if (ctx == NULL)
		err_sys("bad ctx new");
	 if (CyaSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem",
        SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        err_sys("Error loading server-cert.pem");
        return EXIT_FAILURE;
    }
    if (CyaSSL_CTX_use_PrivateKey_file(ctx, "../certs/server-key.pem",
        SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        err_sys("Error loading server-key.pem");
        return EXIT_FAILURE;
    }

    printf("Waiting for a connection...\n");

	tcp_accept(&sockfd, &clientfd, NULL, yasslPort, 1, 0);

	if ((ssl = CyaSSL_new(ctx)) == NULL)
		err_sys("bad cyassl setup");

	if (CyaSSL_set_fd(ssl, clientfd) != SSL_SUCCESS)
		err_sys("bad set fd");

	ret = CyaSSL_read(ssl, buff, sizeof(buff)-1);
	if (ret > 0) {
		buff[ret] = '\0';
		printf("Recieved: %s\n", buff);
		if (ret = CyaSSL_write(ssl, reply, sizeof(reply)-1) < 0)
			err_sys("bad cyassl write");
	} else
		err_sys("bad cyassl read");

	close(sockfd);
	close(clientfd);
	CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();

    return 0;
}