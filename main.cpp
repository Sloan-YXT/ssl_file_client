#include <cstdio>
#include <cstring>
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
#include <termio.h>
#include <sys/wait.h>
#include <string>
#include <pwd.h>
#include "ytp.h"
#include "ssl_util.h"
using namespace std;
#define MAXBUF 4096
#define MAXSERVER 4096
#define PORT 9090
#define ADDR "172.81.227.199"
//SSL_ERROR_ZERO_RETURN
#define DEBUG                           \
    do                                  \
    {                                   \
        printf("debug:%d\n", __LINE__); \
    } while (0)
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
#define ERR_ACTION(f, a) \
    do                   \
    {                    \
        if (f < 0)       \
        {                \
            perror(a);   \
            exit(1);     \
        }                \
    } while (0)
char user_name_local[4096 + 1];
string home_dir;
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

void login(SSL *ssl, int fd)
{
    // setbuf(stdin, NULL);
    // setbuf(stdout, NULL);
    // setbuf(stderr, NULL);
    char buffer[4096 + 1];
    char tmp[4096 + 1];
    char server_buffer[4096 + 1];
    Ytp ytp_login;
    char *p;
restart:
    SSL_read(ssl, server_buffer, MAXSERVER);
    //printf("debug:%d\n", __LINE__);
    //puts(server_buffer);
    p = ytp_login.parser(server_buffer);
    //printf("123");
    printf("%s", p);

    fgets(buffer, MAXBUF + 1, stdin);
    int len = strlen(buffer);
    if (buffer[len - 1] == '\n')
    {
        buffer[len - 1] = 0;
    }
    //strcpy(user_name, buffer);
    // int len1;
    // len1 = htonl(len);
    // send(fd, &len1, sizeof(len1), 0);
    Ytp ytp("LOGIN", "SETUP", LOGIN_PROC, len);
    strcpy(tmp, ytp.content);
    strcat(tmp, buffer);
    SSL_ERR_ACTION(SSL_write(ssl, tmp, strlen(tmp) + 1), "SSL WRITE FAILED IN 64", ssl);
    int n;

    SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
    p = ytp.parser(server_buffer);
    printf("%s", p);
    //username->yxt->passwd;
    //printf("debug:%d\n", __LINE__);
    if (ytp.code == LOGIN_FAILURE)
    {
        goto restart;
    }
    //printf("debug:%d\n", __LINE__);
    struct termios tty;
    unsigned short tty_flags;
    tcgetattr(fileno(stdin), &tty);
    tty_flags = tty.c_lflag;
    //DEBUG;
    tty.c_lflag &= ~(ECHO | ECHOE | ECHONL | ECHOK);
    //int tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY);
    tcsetattr(fileno(stdin), TCSANOW, &tty);
    //flockfile(stdin);
    fgets(buffer, MAXBUF + 1, stdin);
    printf("\r\n");
    len = strlen(buffer);
    //len1 = htonl(len);
    //send(fd, &len1, sizeof(len1), 0);
    if (buffer[len - 1] == '\n')
    {
        buffer[len - 1] = 0;
    }
    ytp.setArgs("LOGIN", "SETUP", LOGIN_PROC, len);
    strcpy(tmp, ytp.content);
    strcat(tmp, buffer);
    SSL_ERR_ACTION(SSL_write(ssl, tmp, strlen(tmp) + 1), "SSL WRITE FAILED IN 64", ssl);
    while (1)
    {

        SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
        //puts(server_buffer);
        p = ytp.parser(server_buffer);
        printf("%s", p);
        if (ytp.code > 0)
        {

            tty.c_lflag = tty_flags;
            tcsetattr(fileno(stdin), TCSANOW, &tty);
            printf("\r\n");
            //funlockfile(stdin);
            int pid = fork();
            if (pid == 0)
            {
                execlp("reset", "reset", NULL);
            }
            else
            {
                wait(NULL);
            }
            break;
        }
        SSL_ERR_ACTION(n = SSL_read(ssl, server_buffer, MAXSERVER + 1), "SSL READ FAILED IN 65", ssl);
        p = ytp.parser(server_buffer);
        printf("%s", p);
        fgets(buffer, MAXBUF + 1, stdin);
        printf("\r\n");
        len = strlen(buffer);
        //len1 = htonl(len);
        if (buffer[len - 1] == '\n')
        {
            buffer[len - 1] = 0;
        }
        //send(fd, &len1, sizeof(len1), 0);
        ytp.setArgs("LOGIN", "SETUP", LOGIN_PROC, len);
        strcpy(tmp, ytp.content);
        strcat(tmp, buffer);
        SSL_ERR_ACTION(SSL_write(ssl, tmp, strlen(tmp) + 1), "SSL WRITE FAILED IN 64", ssl);
        //SSL_ERR_ACTION(SSL_write(ssl, buffer, len), "SSL WRITE FAILED IN 64", ssl);
    }
}
SSL *ssl;
void clean(void)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}
int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    SSL_CTX *ctx;

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
    atexit(clean);
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    login(ssl, sockfd);
    char cmd_buffer[4096 + 1];
    char server_buffer[4096 + 1];
    char response_buffer[4096 + 1];
    Ytp ytp_cmd;
    char *part1;
    int n;
    struct passwd *user_info = getpwuid(getuid());
    strcpy(user_name_local, user_info->pw_name);
    home_dir = "/home/" + string(user_name_local);
    if (strcmp(user_name_local, "root") == 0)
    {
        home_dir = "/root";
    }
    ERR_ACTION(chdir(home_dir.c_str()), "cd to home failed");
    while (1)
    {
        printf("ytp>");
        fflush(stdout);
        fgets(cmd_buffer, 4096, stdin);
        len = strlen(cmd_buffer);
        if (len != 0 && cmd_buffer[len - 1] == '\n')
        {
            cmd_buffer[len - 1] = 0;
        }
        char cmd_tmp[4096 + 1];
        strcpy(cmd_tmp, cmd_buffer);
        part1 = strtok(cmd_tmp, " ");
        if (strcmp(part1, "getfile") != 0 && strcmp(part1, "sendfile") != 0 && strcmp("lcd", part1) != 0 && strcmp("lls", part1) != 0 && strcmp("lmkdir", part1) != 0 && strcmp("ltouch", part1) != 0 && strcmp("ldir", part1) != 0 && strcmp("lrm", part1) != 0 && strcmp("lpwd", part1) != 0)
        {
            ytp_cmd.setArgs("CMD", "ACTIVE", CMD, strlen(cmd_buffer) + 1);
            strcpy(response_buffer, ytp_cmd.content);
            strcat(response_buffer, cmd_buffer);
            n = SSL_write(ssl, response_buffer, strlen(response_buffer) + 1);
            SSL_ERR_ACTION(n, "write failed in 228", ssl);
            n = SSL_read(ssl, server_buffer, 4096 + 1);
            SSL_ERR_ACTION(n, "read failed in 228", ssl);
            char *p = ytp_cmd.parser(server_buffer);
            printf("%s\n", p);
        }
        else if (strcmp(part1, "getfile") != 0 && strcmp(part1, "sendfile") != 0)
        {
            char pdir[4096 + 1] = {0};

            if (strcmp(part1, "lcd") == 0)
            {

                char *part2, *part3;
                part2 = strtok(NULL, " ");
                part3 = strtok(NULL, " ");
                if (part3 != NULL)
                {
                    printf("too much arguments\n");
                }
                else if (part2 == NULL)
                {
                    getcwd(pdir, 4096);
                    printf("now in %s\n", pdir);
                }
                else if (strcmp("~", part2) == 0)
                {
                    int res = chdir(home_dir.c_str());
                    if (res < 0)
                    {
                        perror("lcd failed");
                    }
                    getcwd(pdir, 4096);
                    printf("now in %s\n", pdir);
                }
                else
                {
                    int res = chdir(part2);
                    if (res < 0)
                    {
                        perror("lcd failed");
                    }
                    getcwd(pdir, 4096);
                    printf("now in %s\n", pdir);
                }
            }
            else
            {
                memmove(part1, part1 + 1, strlen(part1));
                //printf("debug:local cmd:%s\n", part1);
                char *cmd_list[40];
                cmd_list[0] = part1;
                char *tmp;
                for (int i = 1; i < 40; i++)
                {
                    tmp = strtok(NULL, " ");
                    cmd_list[i] = tmp;
                    if (tmp == NULL)
                    {
                        break;
                    }
                }
                int pid = fork();
                if (pid == 0)
                {
                    execvp(part1, cmd_list);
                    perror("execv cmd failed");
                    exit(1);
                }
                else
                {
                    wait(NULL);
                }
            }
        }
        else if (strcmp(part1, "sendfile") == 0)
        {
            char *part2, *part3;
            part2 = strtok(NULL, " ");
            part3 = strtok(NULL, " ");
            if (part2 == NULL)
            {
                printf("too few arguments\n");
                continue;
            }
            if (part3 != NULL)
            {
                printf("too much arguments\n");
                continue;
            }
            FILE *file = fopen(part2, "r");
            if (file == NULL)
            {
                perror("file doesn't exist");
                continue;
            }
            fseek(file, 0, SEEK_END);
            len = ftell(file);
            //printf("\nlen:%d\n", len);
            int hlen = htonl(len);
            ytp_cmd.setArgs("FILE", "ACTIVE", FSM, len + strlen("sendfile") + 1);
            strcpy(response_buffer, ytp_cmd.content);
            strcat(response_buffer, cmd_buffer);
            n = SSL_write(ssl, response_buffer, strlen(response_buffer) + 1);
            SSL_ERR_ACTION(n, "ssl write ytp failed in sendfile", ssl);
            n = send(sockfd, &hlen, sizeof(hlen), 0);
            ERR_ACTION(n, "sendfile len send len failed");
            int filefd = fileno(file);
            fseek(file, 0, SEEK_SET);
            void *addr_png_1;
            if ((addr_png_1 = mmap(NULL, len, PROT_READ, MAP_SHARED, filefd, 0)) == MAP_FAILED)
            {
                perror("mmap failed in sendfile");
                exit(1);
            };
            n = SSL_write(ssl, addr_png_1, len);
            SSL_ERR_ACTION(n, "ssl write failed", ssl);
            ERR_ACTION(munmap(addr_png_1, len), "munmap failed in sendfile");
            n = SSL_read(ssl, cmd_buffer, 4096 + 1);
            char *p = ytp_cmd.parser(cmd_buffer);
            printf("%s\n", p);
        }
    }
}