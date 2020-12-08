enum status
{
    LOGIN_SUCCESS = 1,

};
class Ytp
{
public:
    char *type;
    char *status;
    int code;
    int len;
    char *content;
    Ytp(char *type, char *status, int code, int len);
    Ytp();
    char *parser(char *message);
    ~Ytp();
};