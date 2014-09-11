
#include <stdio.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include "ssl.h"

static int __attribute__ ((__format__ (__printf__, 1, 2))) ssl_error(const char * fmt, ...)
{
    char str[1024];
    int n;
    va_list va;
    int done;

    va_start(va, fmt);
    n = vsnprintf(str, sizeof str, fmt, va);
    va_end(va);
    if (n < (int )sizeof str) {
        if (str[n - 1] == '\n')
            n --;
    }

    done = 0;
    for (;;) {
        unsigned long err;

        err = ERR_get_error();
        if (err == 0)
            break;

        ERR_error_string_n(err, str + n, sizeof str - n);
        fprintf(stderr, "%s\n", str);
        done ++;
    }

    if (!done)
        fprintf(stderr, "%s\n", str);

    return 0;
}

static int ssl_check_certificate(const char * my_name, const char * dist_name, const SSL * ssl)
{
    X509 *client_cert;
    const char * me = my_name ? my_name : "Unknown";
    const char * dist = dist_name ? dist_name : "Unknown";

    printf("%s %s SSL connection using %s\n", me, dist, SSL_get_cipher(ssl));

    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        char * subject = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        char * issuer = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);

        printf("%s %s Certificate: [ subject = <%s> ], [issuer = <%s>]\n", me, dist, subject ? subject : "", issuer ? issuer : "");

        if (subject != NULL)
            OPENSSL_free(subject);

        if (issuer != NULL)
            OPENSSL_free(issuer);

        X509_free(client_cert);

    } else
        printf("%s %s Certificate: None\n", me, dist);

    return 0;
}

static SSL_CTX * ssl_ctx_init(const char * name, const SSL_METHOD *meth, const char * certificate, const int certificate_type, const char * private_key, const int private_key_type)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ssl_error("%s Failed to get a new ctx ", name);
        goto err;
    }

    if (certificate != NULL) {

        if (SSL_CTX_use_certificate_file(ctx, certificate, certificate_type) <= 0) {
            ssl_error("%s Failed to use certificate <%s> ", name, certificate);
            goto free_ctx_err;
        }
    }

    if (private_key != NULL) {
        if (SSL_CTX_use_PrivateKey_file(ctx, private_key, private_key_type) <= 0) {
            ssl_error("%s Failed to use private key <%s> ", name, private_key);
            goto free_ctx_err;
        }
    }

    if (certificate != NULL && private_key != NULL) {

        if (!SSL_CTX_check_private_key(ctx)) {
            fprintf(stderr, "%s Private key <%s> does not match the certificate public key <%s>\n", name, private_key, certificate);
            goto free_ctx_err;
        }
    }

    return ctx;

free_ctx_err:
    SSL_CTX_free(ctx);
err:
    return NULL;
}

static ssize_t ssl_write(const char * my_name, const char * dist_name, SSL * ssl, const void * buff, const size_t buff_size)
{
    ssize_t done;

    done = 0;

    while ((size_t)done < buff_size) {
        int size;

        size = SSL_write(ssl, ((const char *)buff) + done, buff_size - done);
        if (size < 0) {
            ssl_error("%s%s%s Failed to write ", my_name ? my_name : "", dist_name ? " ": "", dist_name ? dist_name : "");
            goto err;
        }

        if (size == 0) {
            printf("%s%s%s Hanged up\n", my_name ? my_name : "", dist_name ? " ": "", dist_name ? dist_name : "");
            done = 0;
            break;
        }

        done += (ssize_t)size;
    }

    return done;

err:
    return -1;
}

static ssize_t ssl_read(const char * my_name, const char * dist_name, SSL * ssl, void * buff, const size_t buff_size)
{
    int size;

    size = SSL_read(ssl, buff, buff_size);
    if (size < 0)
        ssl_error("%s%s%s Failed to read ", my_name ? my_name : "", dist_name ? " ": "", dist_name ? dist_name : "");
    else if (size == 0)
        printf("%s%s%s Hanged up\n", my_name ? my_name : "", dist_name ? " ": "", dist_name ? dist_name : "");

    return (ssize_t)size;
}

pthread_mutex_t ssl_used_lock = PTHREAD_MUTEX_INITIALIZER;
static int ssl_used_count = 0;

static void ssl_lib_init(void)
{
    pthread_mutex_lock(&ssl_used_lock);

    if (ssl_used_count == 0) {
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        printf("libssl is initialized\n");
    }

    ssl_used_count ++;

    pthread_mutex_unlock(&ssl_used_lock);
}

static void ssl_lib_free(void)
{
    pthread_mutex_lock(&ssl_used_lock);

    ssl_used_count --;
    if (ssl_used_count == 0) {
        sk_free((void *)SSL_COMP_get_compression_methods());
        ENGINE_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        ERR_remove_thread_state(NULL);
        EVP_cleanup();
        printf("libssl is freed\n");
    }

    pthread_mutex_unlock(&ssl_used_lock);
}

int ssl_serv_init(struct ssl_serv * serv, const char * certificate, const int certificate_type, const char * private_key, const int private_key_type, const struct in_addr local_ip, const uint16_t local_port)
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    int sock;
    struct sockaddr_in sin;
    int flag;

    ssl_lib_init();

    memset(serv, 0, sizeof serv[0]);

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = local_ip;
    sin.sin_port = htons(local_port);

    snprintf(serv->name, sizeof serv->name, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

    meth = SSLv23_server_method();
    if (meth == NULL) {
        ssl_error("%s Failed to get server method ", serv->name);
        goto err;
    }

    ctx = ssl_ctx_init(serv->name, meth, certificate, certificate_type, private_key, private_key_type);
    if (ctx == NULL)
        goto err;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "%s Failed to get socket : %s\n", serv->name, strerror(errno));
        goto free_ctx_err;
    }

    flag = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag) < 0) {
        fprintf(stderr, "%s Failed to set REUSEADDR flag : %s\n", serv->name, strerror(errno));
        goto close_sock_err;
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        fprintf(stderr, "%s Failed to bind : %s\n", serv->name, strerror(errno));
        goto close_sock_err;
    }

    if (listen(sock, 5) < 0) {
        fprintf(stderr, "%s Failed to listen : %s\n", serv->name, strerror(errno));
        goto close_sock_err;
    }

    serv->sock = sock;
    serv->ctx = ctx;
    pthread_mutex_init(&serv->ssl_cnx_lock, NULL);

    printf("%s Ready\n", serv->name);
    return 0;

close_sock_err:
    close(sock);
free_ctx_err:
    SSL_CTX_free(ctx);
err:
    ssl_lib_free();
    return -1;
}

static inline void cnx_link(struct ssl_serv * serv, struct ssl_cnx *cnx)
{
    pthread_mutex_lock(&serv->ssl_cnx_lock);
    cnx->ssl_cnx_next = NULL;
    cnx->ssl_cnx_prev = serv->ssl_cnx_last;
    if (serv->ssl_cnx_last != NULL)
        serv->ssl_cnx_last->ssl_cnx_next = cnx;
    else
        serv->ssl_cnx_first = cnx;
    serv->ssl_cnx_last = cnx;
    pthread_mutex_unlock(&serv->ssl_cnx_lock);
}

static inline void cnx_unlink(struct ssl_serv * serv, struct ssl_cnx *cnx, const int locked)
{
    if (locked)
        pthread_mutex_lock(&serv->ssl_cnx_lock);

    if (cnx->ssl_cnx_prev != NULL)
        cnx->ssl_cnx_prev->ssl_cnx_next = cnx->ssl_cnx_next;
    else
        serv->ssl_cnx_first = cnx->ssl_cnx_next;

    if (cnx->ssl_cnx_next != NULL)
        cnx->ssl_cnx_next->ssl_cnx_prev = cnx->ssl_cnx_prev;
    else
        serv->ssl_cnx_last = cnx->ssl_cnx_prev;

    cnx->ssl_cnx_prev = NULL;
    cnx->ssl_cnx_next = NULL;

    if (locked)
        pthread_mutex_unlock(&serv->ssl_cnx_lock);
}

int ssl_serv_accept(struct ssl_serv * serv, const int nonblock, struct ssl_cnx **new_cnx)
{
    struct sockaddr_in sin;
    socklen_t sin_len;
    struct ssl_cnx * cnx;

    cnx = NULL;
    if (nonblock) {
        struct pollfd fds;
        int ret;

        fds.fd = serv->sock;
        fds.events = POLLIN;
        fds.revents = 0;

        ret = poll(&fds, 1, 0);
        if (ret < 0) {
            fprintf(stderr, "%s Failed to poll : %s\n", serv->name, strerror(errno));
            goto err;
        }

        if (fds.revents == 0)
            goto no_cnx;
    }

    cnx = calloc(1, sizeof cnx[0]);
    if (cnx == NULL) {
        fprintf(stderr, "%s Failed to allocate a new cnx : %s\n", serv->name, strerror(errno));
        goto err;
    }

    memset(&sin, 0, sizeof sin);
    sin_len = sizeof sin;
    cnx->fd = accept(serv->sock, (struct sockaddr *)&sin, &sin_len);
    if (cnx->fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            goto no_cnx;
        fprintf(stderr, "%s Failed to accept : %s\n", serv->name, strerror(errno));
        goto free_cnx_err;
    }

    snprintf(cnx->name, sizeof cnx->name, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

    printf("%s %s New cnx\n", serv->name, cnx->name);

    cnx->ssl = SSL_new(serv->ctx);
    if (cnx->ssl == NULL) {
        ssl_error("%s %s Failed to create a new ssl session ", serv->name, cnx->name);
        goto close_err;
    }

    if (SSL_set_fd(cnx->ssl, cnx->fd) == 0) {
        ssl_error("%s %s Failed to set fd ", serv->name, cnx->name);
        goto free_ssl_err;
    }

    if (SSL_accept(cnx->ssl) <= 0) {
        ssl_error("%s %s Failed to accept ssl ", serv->name, cnx->name);
        goto no_cnx;
    }
    printf("%s %s SSL connection established\n", serv->name, cnx->name);

    if (ssl_check_certificate(serv->name, cnx->name, cnx->ssl) < 0)
        goto no_cnx;

    cnx_link(serv, cnx);
    *new_cnx = cnx;
    return 1;

no_cnx:
    if (cnx != NULL) {

        if (cnx->ssl != NULL) {
            SSL_free(cnx->ssl);
            fprintf(stderr, "%s %s SSL connection rejecected\n", serv->name, cnx->name);
        }
        free(cnx);

        if (cnx->fd >= 0)
            close(cnx->fd);
    }
    *new_cnx = NULL;
    return 0;

free_ssl_err:
    SSL_free(cnx->ssl);
close_err:
    close(cnx->fd);
free_cnx_err:
    free(cnx);
err:
    return -1;
}

static void do_cnx_free(struct ssl_serv * serv, struct ssl_cnx * cnx, const int locked)
{
    cnx_unlink(serv, cnx, locked);
    close(cnx->fd);
    SSL_free(cnx->ssl);
    printf("%s %s Closed\n", serv->name, cnx->name);
    free(cnx);
}

void ssl_cnx_free(struct ssl_serv * serv, struct ssl_cnx * cnx)
{
    do_cnx_free(serv, cnx, 1);
}

void ssl_serv_free(struct ssl_serv * serv)
{
    pthread_mutex_lock(&serv->ssl_cnx_lock);
    while (serv->ssl_cnx_first != NULL)
        do_cnx_free(serv, serv->ssl_cnx_first, 0);
    pthread_mutex_unlock(&serv->ssl_cnx_lock);

    SSL_CTX_free(serv->ctx);
    close(serv->sock);
    serv->ctx = NULL;
    serv->sock = -1;
    printf("%s Closed\n", serv->name);
    ssl_lib_free();
}

int ssl_cnx_read(struct ssl_serv * serv, struct ssl_cnx * cnx, void * buff, const size_t buff_size)
{
    return ssl_read(serv->name, cnx->name, cnx->ssl, buff, buff_size);
}

int ssl_cnx_write(struct ssl_serv * serv, struct ssl_cnx * cnx, const void * buff, const size_t buff_size)
{
    return ssl_write(serv->name, cnx->name, cnx->ssl, buff, buff_size);
}

int ssl_client_init(struct ssl_client * cl, const char * certificate, const int certificate_type, const char * private_key, const int private_key_type, const struct in_addr local_addr, const uint16_t local_port, const struct in_addr host_addr, const uint16_t host_port, const int nonblock)
{
    struct sockaddr_in source;
    struct sockaddr_in dest;
    const SSL_METHOD *meth;
    char dest_name[SSL_PEER_NAME_SIZE];

    ssl_lib_init();

    snprintf(dest_name, sizeof dest_name, "%s:%d", inet_ntoa(host_addr), host_port);

    if (cl->fd < 0) {

        snprintf(cl->name, sizeof cl->name, "%s:%d", inet_ntoa(local_addr), local_port);
        cl->fd = socket(AF_INET, SOCK_STREAM, 0);
        if (cl->fd < 0) {
            fprintf(stderr, "%s Failed to get a new socket : %s\n", cl->name, strerror(errno));
            goto err;
        }


        if (nonblock) {
            int flags;

            flags = fcntl(cl->fd, F_GETFL);
            if (fcntl(cl->fd, flags | O_NONBLOCK) < 0) {
                fprintf(stderr, "%s Failed to set NONBLOCK flag : %s\n", cl->name, strerror(errno));
                goto close_err;
            }
        }

        memset(&source, 0, sizeof source);
        source.sin_family = AF_INET;
        source.sin_addr = local_addr;
        source.sin_port = htons(local_port);

        if (bind(cl->fd, (struct sockaddr *)&source, sizeof source) < 0) {
            fprintf(stderr, "%s Failed to bind : %s\n", cl->name, strerror(errno));
            goto close_err;
        }

        if (source.sin_addr.s_addr == INADDR_ANY || source.sin_port == 0) {
            socklen_t sin_len = sizeof source;

            if (getsockname(cl->fd, (struct sockaddr *)&source, &sin_len) < 0)
                fprintf(stderr, "%s Failed to get my socket name : %s\n", cl->name, strerror(errno));
            else {
                printf("%s is now known as %s:%d\n", cl->name, inet_ntoa(source.sin_addr), ntohs(source.sin_port));
                snprintf(cl->name, sizeof cl->name, "%s:%d", inet_ntoa(source.sin_addr), ntohs(source.sin_port));
            }
        }
    }

    memset(&dest, 0, sizeof dest);
    dest.sin_family = AF_INET;
    dest.sin_addr = host_addr;
    dest.sin_port = htons(host_port);

    if (connect(cl->fd, (struct sockaddr *)&dest, sizeof dest) < 0) {
        if (errno == EINPROGRESS || errno == EINTR)
            goto not_finished;

        fprintf(stderr, "%s Failed to connect to %s : %s\n", cl->name, dest_name, strerror(errno));
        goto close_err;
    }

    printf("%s Connected to %s\n", cl->name, dest_name);

    meth = SSLv23_client_method();
    if (meth == NULL) {
        ssl_error("%s Failed to get SSL method ", cl->name);
        goto close_err;
    }

    cl->ctx = ssl_ctx_init(cl->name, meth, certificate, certificate_type, private_key, private_key_type);
    if (cl->ctx == NULL)
        goto close_err;

    cl->ssl = SSL_new(cl->ctx);
    if (cl->ssl == NULL) {
        ssl_error("%s Failed to get SSL ", cl->name);
        goto free_ctx_err;
    }

    if (SSL_set_fd(cl->ssl, cl->fd) == 0) {
        ssl_error("%s Failed to set fd ", cl->name);
        goto free_ssl_err;
    }

    if (SSL_connect(cl->ssl) <= 0) {
        ssl_error("%s Failed to connect SSL to %s", cl->name, dest_name);
        goto free_ssl_err;
    }

    if (ssl_check_certificate(cl->name, dest_name, cl->ssl) < 0)
        goto free_ssl_err;

    return 1;

not_finished:
    return 0;

free_ssl_err:
    SSL_free(cl->ssl);
free_ctx_err:
    SSL_CTX_free(cl->ctx);
close_err:
    close(cl->fd);
    cl->fd = -1;
err:
    ssl_lib_free();
    return -1;
}

int ssl_client_write(struct ssl_client * cl, const void * buff, const size_t buff_size)
{
    return ssl_write(cl->name, NULL, cl->ssl, buff, buff_size);
}

int ssl_client_read(struct ssl_client * cl, void * buff, const size_t buff_size)
{
    return ssl_read(cl->name, NULL, cl->ssl, buff, buff_size);
}

void ssl_client_free(struct ssl_client * cl)
{
    if (cl->ssl != NULL)
        SSL_free(cl->ssl);

    if (cl->ctx != NULL)
        SSL_CTX_free(cl->ctx);

    if (cl->fd >= 0)
        close(cl->fd);

    printf("%s Closed\n", cl->name);
    ssl_client_set_default(cl);
    ssl_lib_free();
}
