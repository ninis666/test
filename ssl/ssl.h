
#ifndef __SSL_H__
# define __SSL_H__

#define SSL_PEER_NAME_SIZE (sizeof "xxx.xxx.xxx.xxx:xxxxx")

struct ssl_cnx {
    SSL * ssl;
    int fd;
    struct ssl_cnx * ssl_cnx_next;
    struct ssl_cnx * ssl_cnx_prev;
    char name[SSL_PEER_NAME_SIZE];
};

struct ssl_serv {
    int sock;
    SSL_CTX *ctx;
    pthread_mutex_t ssl_cnx_lock;
    struct ssl_cnx * ssl_cnx_first;
    struct ssl_cnx * ssl_cnx_last;
    char name[SSL_PEER_NAME_SIZE];
};

int ssl_serv_init(struct ssl_serv * serv, const char * certificate, const int certificate_type, const char * private_key, const int private_key_type, const struct in_addr local_ip, const uint16_t local_port);
int ssl_serv_accept(struct ssl_serv * serv, const int nonblock, struct ssl_cnx **new_cnx);
void ssl_serv_free(struct ssl_serv * serv);

int ssl_cnx_read(struct ssl_serv * serv, struct ssl_cnx * cnx, void * buff, const size_t buff_size);
int ssl_cnx_write(struct ssl_serv * serv, struct ssl_cnx * cnx, const void * buff, const size_t buff_size);

void ssl_cnx_free(struct ssl_serv * serv, struct ssl_cnx * cnx);

struct ssl_client {
    SSL_CTX * ctx;
    SSL * ssl;
    int fd;
    char name[SSL_PEER_NAME_SIZE];
};

int ssl_client_init(struct ssl_client * cl, const char * certificate, const int certificate_type, const char * private_key, const int private_key_type, const struct in_addr local_addr, const uint16_t local_port, const struct in_addr host_addr, const uint16_t host_port, const int nonblock);
void ssl_client_free(struct ssl_client * cl);

static inline void ssl_client_set_default(struct ssl_client * cl)
{
    memset(cl, 0, sizeof cl[0]);
    cl->fd = -1;
}

int ssl_client_write(struct ssl_client * cl, const void * buff, const size_t buff_size);
int ssl_client_read(struct ssl_client * cl, void * buff, const size_t buff_size);

#endif
