
#ifndef __event_ssl_h__
# define __event_ssl_h__

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 19720

#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>

struct ssl_client;
typedef int(*ssl_client_connected_fun_t)(struct ssl_client *);
typedef int(*ssl_client_read_fun_t)(struct ssl_client *, struct evbuffer *src);

struct ssl_client {
    char name[sizeof "xxx.xxx.xxx.xxx:xxxxx"];
    SSL_CTX *ssl_ctx;
    SSL * ssl;
    struct event_base *base;
    struct bufferevent *bev;
    ssl_client_connected_fun_t connected_fun;
    ssl_client_read_fun_t      read_fun;
};

struct ssl_server {
    SSL_CTX *ctx;
    struct event_base *base;
    struct evconnlistener *listener;
    char name[sizeof "255.255.255.255.65535"];
    ssl_client_connected_fun_t connected_fun;
    ssl_client_read_fun_t read_fun;
};

int ssl_server_init(struct ssl_server * srv, const char *keypath, const char *certpath, const struct sockaddr_in * source);
int ssl_server_run(struct ssl_server * srv);

int ssl_client_init(struct ssl_client * cl, const struct sockaddr_in * dest);
int ssl_client_run(struct ssl_client * cl);
void ssl_client_deinit(struct ssl_client * cl);

int ssl_client_write(struct ssl_client * cl, const char * cmd, const int from_cb);
char * ssl_client_read(struct ssl_client * cl, const int from_cb);

#endif
