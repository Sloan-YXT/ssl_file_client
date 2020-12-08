#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include "ytp.h"
using namespace std;
#define MAXBUF 1024
#define MAXSERVER 4096
#define PORT 9090
#define ADDR "172.81.227.199"
//SSL_ERROR_ZERO_RETURN
#define SSL_ERR_ACTION(f, a, ssl)                  \
    do                                             \
    {                                              \
        if (f <= 0)                                \
        {                                          \
            perror(a);                             \
            ERR_print_errors_fp(stdout);           \
            printf("%d\n", SSL_get_error(ssl, f)); \
            exit(1);                               \
        }                                          \
    } while (0)

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("无证书信息！\n");
}
char buffer[MAXBUF + 1];
char server_buffer[MAXSERVER + 1];
void login(SSL *ssl, int fd)
{
    SSL_read(ssl, server_buffer, MAXSERVER);
    printf("%s", server_buffer);
    fgets(buffer, MAXBUF + 1, stdin);
    int len = strlen(buffer);
    if (buffer[len - 1] == '\n')
    {
        buffer[len - 1] = 0;
    }
    int len1;
    len1 = htonl(len);
    send(fd, &len1, sizeof(len1), 0);
    SSL_ERR_ACTION(SSL_write(ssl, buffer, len), "SSL WRITE FAILED IN 64", ssl);
    int n;
    char *p;
    Ytp ytp;
    SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
    p = ytp.parser(server_buffer);
    printf("%s", p);
    //username->yxt->passwd;
    fgets(buffer, MAXBUF + 1, stdin);
    len = strlen(buffer);
    //len1 = htonl(len);
    //send(fd, &len1, sizeof(len1), 0);
    SSL_ERR_ACTION(SSL_write(ssl, buffer, len), "SSL WRITE FAILED IN 64", ssl);
    if (buffer[len - 1] == '\n')
    {
        buffer[len - 1] = 0;
    }
    while (1)
    {

        SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
        p = ytp.parser(server_buffer);
        printf("%s", p);
        if (ytp.code > 0)
        {
            break;
        }
        SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
        p = ytp.parser(server_buffer);
        printf("%s", p);
        fgets(buffer, MAXBUF + 1, stdin);
        len = strlen(buffer);
        //len1 = htonl(len);
        if (buffer[len - 1] == '\n')
        {
            buffer[len - 1] = 0;
        }
        //send(fd, &len1, sizeof(len1), 0);
        SSL_ERR_ACTION(SSL_write(ssl, buffer, len), "SSL WRITE FAILED IN 64", ssl);
    }
}
int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;

    SSL_CTX *ctx;
    SSL *ssl;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);
    if (inet_aton(ADDR, (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    bzero(buffer, MAXBUF + 1);
    login(ssl, sockfd);
    while (1)
    {
    }
}