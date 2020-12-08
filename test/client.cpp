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
using namespace std;
#define MAXBUF 1024
#define PORT 7899
#define ADDR "172.81.227.199"
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

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
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
    strcpy(buffer, "hello ssl server!!!");
    len = SSL_write(ssl, buffer, strlen(buffer));
    if (len < 0)
        printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功，共发送了%d个字节！\n", buffer, len);
    // len = SSL_write(ssl, buffer, strlen(buffer));
    // if (len < 0)
    //     printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buffer, errno, strerror(errno));
    // else
    //     printf("消息'%s'发送成功，共发送了%d个字节！\n", buffer, len);
    // len = SSL_write(ssl, buffer, strlen(buffer));
    // if (len < 0)
    //     printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buffer, errno, strerror(errno));
    // else
    //     printf("消息'%s'发送成功，共发送了%d个字节！\n", buffer, len);
    FILE *png_1 = fopen("1.png", "r");
    fseek(png_1, 0, SEEK_END);
    len = ftell(png_1);
    printf("\nlen:%d\n", len);
    int hlen = htonl(len);
    int n = send(sockfd, &hlen, sizeof(len), 0);
    //len = SSL_write(ssl, &hlen, sizeof(len));
    if (n < 0)
        printf("消息'%d'发送失败！错误代码是%d，错误信息是'%s'\n", len, errno, strerror(errno));
    else
        printf("消息'%d'发送成功，共发送了%d个字节！\n", len, n);
    int filefd = fileno(png_1);
    fseek(png_1, 0, SEEK_SET);
    void *addr_png_1;
    if ((addr_png_1 = mmap(NULL, len, PROT_READ, MAP_SHARED, filefd, 0)) == MAP_FAILED)
    {
        perror("mmap failed");
        exit(1);
    };
    puts((char *)addr_png_1);
    n = SSL_write(ssl, addr_png_1, len);
    if (n < 0)
        printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功，共发送了%d个字节！\n", addr_png_1, n);
finish:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}