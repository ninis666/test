
#include <openssl/err.h>
#include <pthread.h>
#include <event2/thread.h>
#include "event_ssl.h"

#define PFX "[EV_SSL] "
#include "logger.h"
#include "xmalloc.h"

#define LOCKING_ERROR_NOT_FATAL 0
#ifndef LOCKING_ERROR_NOT_FATAL
# define LOCKING_ERROR_NOT_FATAL 0
#endif

static void read_cb(struct bufferevent *bev, void *arg)
{
    struct ssl_client * cl = arg;

    if (cl->bev != bev) {
        log_warn("%s Unexpected client / bev : %p != %p", cl->name, bev, cl->bev);
        goto err;
    }

    if (cl->read_fun != NULL) {
        struct evbuffer *src;

        src = bufferevent_get_input(bev);
        if (src == NULL) {
            log_err("%s Failed to get input", cl->name);
            goto err;
        }

        if (evbuffer_get_length(src) != 0)
            cl->read_fun(cl, src);
    }

err:
    return;
}

static size_t snprintf_openssl_err(struct bufferevent *bev, char * res, const size_t res_size)
{
    unsigned long err;
    size_t used;

    used = 0;
    res[0] = 0;
    while ((err = (bufferevent_get_openssl_error(bev)))) {
        const char *msg = ERR_reason_error_string(err);
        const char *lib = ERR_lib_error_string(err);
        const char *fun = ERR_func_error_string(err);
        int n;

        n = snprintf(res + used, res_size - used, "%s %s : %s\n", lib, fun, msg);
        if (n < 0 || (size_t)n >= res_size - used)
            break;
        used += (size_t)n;
    }

    if (used > 0 && res[used - 1] == '\n')
        res[--used] = 0;

    return used;
}

static void client_event_cb(struct bufferevent *bev, short what, void *arg)
{
    struct ssl_client * cl = arg;
    const int errno_save = errno;

    if (bev != cl->bev) {
        log_warn("%s Invalid bev (%p != %p)", cl->name, bev, cl->bev);
        goto err;
    }

    log_info("%s what : %x", cl->name, what);

    if (what & BEV_EVENT_CONNECTED) {
        log_info("%s Connected", cl->name);
        if (cl->connected_fun != NULL)
            cl->connected_fun(cl);
    } else if (what & BEV_EVENT_ERROR) {
        char msg[1024];

        if (snprintf_openssl_err(bev, msg, sizeof msg) != 0)
            log_err("%s SSL error : %s", cl->name, msg);
        else if (errno_save != 0)
            log_err("%s TCP error : %s", cl->name, strerror(errno_save));
        else
            log_err("%s Unexpected TCP error happened", cl->name);
    }

err:
    return;
}

static void client_accept_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *from, int from_len, void *arg)
{
    const struct sockaddr_in * sin  = (struct sockaddr_in *)from;
    const struct ssl_server * srv = arg;
    struct ssl_client * cl;
    struct evbuffer * evb;

    cl = calloc(1, sizeof cl[0]);
    if (cl == NULL) {
        log_err("%s:%d Failed to allocate ssl_client : %s", inet_ntoa(sin->sin_addr), htons(sin->sin_port), strerror(errno));
        goto close_err;
    }

    snprintf(cl->name, sizeof cl->name, "%s:%d", inet_ntoa(sin->sin_addr), htons(sin->sin_port));
    log_info("%s new connection from %s", srv->name, cl->name);

    cl->ssl = SSL_new(srv->ctx);
    if (cl->ssl == NULL) {
        log_err("%s Failed to create a SSL session for <%s>", srv->name, cl->name);
        goto free_cl_err;
    }

    cl->bev = bufferevent_openssl_socket_new(srv->base, sock, cl->ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (cl->bev == NULL) {
        log_err("%s Failed to create a bufferevent for <%s>", srv->name, cl->name);
        goto free_ssl_err;
    }

    evb = bufferevent_get_output(cl->bev);
    if (evb == NULL) {
        log_warn("%s Failed to get output buffer for <%s>", srv->name, cl->name);
        goto free_bev_err;
    }

    if (evbuffer_enable_locking(evb, NULL) < 0) {
        log_warn("%s Failed to enable locking on output for <%s>", srv->name, cl->name);
        if (!LOCKING_ERROR_NOT_FATAL)
            goto free_bev_err;
    }

    evb = bufferevent_get_input(cl->bev);
    if (evb == NULL) {
        log_warn("%s Failed to get input buffer for <%s>", srv->name, cl->name);
        goto free_bev_err;
    }

    if (evbuffer_enable_locking(evb, NULL) < 0) {
        log_warn("%s Failed to enable locking on input for <%s>", srv->name, cl->name);
        if (!LOCKING_ERROR_NOT_FATAL)
            goto free_bev_err;
    }

    cl->connected_fun = srv->connected_fun;
    cl->read_fun = srv->read_fun;

    bufferevent_setcb(cl->bev, read_cb, NULL, client_event_cb, cl);
    bufferevent_enable(cl->bev, EV_READ | EV_WRITE);
    return;

free_bev_err:
    bufferevent_free(cl->bev);
    cl->ssl = NULL;
free_ssl_err:
    if (cl->ssl != NULL)
        SSL_free(cl->ssl);
free_cl_err:
    free(cl);
close_err:
    evutil_closesocket(sock);
    log_err("%s Connection from <%s:%d> rejected", srv->name, inet_ntoa(sin->sin_addr), htons(sin->sin_port));
}

static pthread_mutex_t ssl_used_lock = PTHREAD_MUTEX_INITIALIZER;
static int ssl_used_count = 0;

static void event_log(int lvl, const char * msg)
{
    log_info("event W%d %s", lvl, msg);
}

static void * lock_allocate(unsigned locktype)
{
    void * ret;

    if ((locktype & EVTHREAD_LOCKTYPE_READWRITE) != 0) {
        pthread_rwlock_t * rwlock;

        if ((locktype & EVTHREAD_LOCKTYPE_RECURSIVE) != 0) {
            log_err("Trying to create a recursive rwlock ?");
            goto err;
        }

        rwlock = calloc(1, sizeof rwlock[0]);
        pthread_rwlock_init(rwlock, NULL);
        ret = rwlock;
    } else {
        pthread_mutex_t * mutex;
        pthread_mutexattr_t attr;

        pthread_mutexattr_init(&attr);

        if ((locktype & EVTHREAD_LOCKTYPE_RECURSIVE) != 0)
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);

        mutex = calloc(1, sizeof mutex[0]);
        pthread_mutex_init(mutex, &attr);
        ret = mutex;
    }

    return ret;

err:
    return NULL;
}

static void lock_free(void *lock, unsigned locktype)
{
    if ((locktype & EVTHREAD_LOCKTYPE_READWRITE) != 0) {
        pthread_rwlock_t * rwlock = lock;
        pthread_rwlock_destroy(rwlock);
        free(rwlock);
    } else {
        pthread_mutex_t * mutex = lock;
        pthread_mutex_destroy(mutex);
    }
}

static int lock_lock(unsigned mode, void * lock)
{
    int ret;

    if (((mode & EVTHREAD_WRITE) != 0 && (mode & EVTHREAD_READ) != 0) ||
        ((mode & EVTHREAD_WRITE) == 0 && (mode & EVTHREAD_READ) == 0)) {
        pthread_mutex_t * mutex = lock;
        if ((mode & EVTHREAD_TRY) != 0)
            ret = pthread_mutex_trylock(mutex);
        else
            ret = pthread_mutex_lock(mutex);

    } else if ((mode & EVTHREAD_WRITE) != 0) {
        pthread_rwlock_t * rwlock = lock;
        if ((mode & EVTHREAD_TRY) != 0)
            ret = pthread_rwlock_trywrlock(rwlock);
        else
            ret = pthread_rwlock_wrlock(rwlock);
    } else if ((mode & EVTHREAD_READ) != 0) {
        pthread_rwlock_t * rwlock = lock;

        if ((mode & EVTHREAD_TRY) != 0)
            ret = pthread_rwlock_tryrdlock(rwlock);
        else
            ret = pthread_rwlock_rdlock(rwlock);
    } else {
        log_err("Invalid lock mode <%#x>", mode);
        return -1;
    }

    return ret;
}

static int lock_unlock(unsigned mode, void * lock)
{
    int ret;

    if (((mode & EVTHREAD_WRITE) != 0 && (mode & EVTHREAD_READ) != 0) ||
        ((mode & EVTHREAD_WRITE) == 0 && (mode & EVTHREAD_READ) == 0)) {
        pthread_mutex_t * mutex = lock;
        ret = pthread_mutex_unlock(mutex);
    } else {
        pthread_rwlock_t * rwlock = lock;
        ret = pthread_rwlock_unlock(rwlock);
    }
    return ret;
}

static void ssl_lib_init(void)
{
    pthread_mutex_lock(&ssl_used_lock);

    if (ssl_used_count == 0) {
        const struct evthread_lock_callbacks lock_cb = {
            .lock_api_version = EVTHREAD_LOCK_API_VERSION,
            .supported_locktypes = EVTHREAD_LOCKTYPE_READWRITE | EVTHREAD_LOCKTYPE_RECURSIVE,
            .alloc = lock_allocate,
            .free = lock_free,
            .lock = lock_lock,
            .unlock = lock_unlock,
        };

        if (1)
            evthread_set_lock_callbacks(&lock_cb);
        event_set_mem_functions(__wrap_malloc, __wrap_realloc, __wrap_free);
        event_set_log_callback(event_log);
        SSL_load_error_strings();
        SSL_library_init();
    }
    ssl_used_count ++;

    pthread_mutex_unlock(&ssl_used_lock);
}

static void ssl_lib_deinit(void)
{
    pthread_mutex_lock(&ssl_used_lock);

    ssl_used_count --;
    if (ssl_used_count == 0)
        ERR_free_strings();

    pthread_mutex_unlock(&ssl_used_lock);
}

int ssl_server_init(struct ssl_server * srv, const char *keypath, const char *certpath, const struct sockaddr_in * source)
{
    SSL_CTX *ctx;
    struct event_base *base;
    struct evconnlistener *listener;

    ssl_lib_init();

    snprintf(srv->name, sizeof srv->name, "%s:%d", inet_ntoa(source->sin_addr), ntohs(source->sin_port));

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        log_warn("%s Failed to get a new server SSL CTX", srv->name);
        goto err;
    }

    if (certpath != NULL) {
        if (!SSL_CTX_use_certificate_chain_file(ctx, certpath)) {
            log_warn("%s Failed to use certificate file <%s> ", srv->name, certpath);
            goto free_ctx_err;
        }
    }

    if (keypath != NULL) {
        if (SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) <= 0) {
            log_warn("%s Failed to use private key <%s> ", srv->name, keypath);
            goto free_ctx_err;
        }
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    base = event_base_new();
    if (base == NULL) {
        log_warn("%s Failed to get event base", srv->name);
        goto free_ctx_err;
    }

    listener = evconnlistener_new_bind(base, client_accept_cb, srv, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)source, sizeof source[0]);
    if (listener == NULL) {
        log_warn("%s Failed to create a listener", srv->name);
        goto free_base_err;
    }

    srv->ctx = ctx;
    srv->base = base;
    srv->listener = listener;
    return 0;

free_base_err:
    event_base_free(base);
free_ctx_err:
    SSL_CTX_free(ctx);
err:
    ssl_lib_deinit();
    return -1;
}

int ssl_server_run(struct ssl_server * srv)
{
    log_info("%s running ...", srv->name);
    event_base_dispatch(srv->base);
    return 0;
}

int ssl_client_init(struct ssl_client * cl, const struct sockaddr_in * dest)
{
    SSL_CTX *ssl_ctx;
    SSL * ssl;
    struct event_base *base;
    struct bufferevent *bev;
    struct evbuffer * evb;

    memset(cl, 0, sizeof cl[0]);

    ssl_lib_init();

    snprintf(cl->name, sizeof cl->name, "%s:%d", inet_ntoa(dest->sin_addr), ntohs(dest->sin_port));

    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
        log_err("%s Failed to get a new client SSL CTX", cl->name);
        goto err;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        log_err("%s Failed to get a new SSL object", cl->name);
        goto free_ctx_err;
    }

    base = event_base_new();
    if (base == NULL) {
        log_warn("%s Failed to get event base", cl->name);
        goto free_ssl_err;
    }

    bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (bev == NULL) {
        log_err("%s Failed to get a buffer event", cl->name);
        goto free_base_err;
    }

    evb = bufferevent_get_output(bev);
    if (evb == NULL) {
        log_warn("%s Failed to get output buffer", cl->name);
        goto free_bev_err;
    }
    if (evbuffer_enable_locking(evb, NULL) < 0) {
        log_warn("%s Failed to enable locking on output", cl->name);
        if (!LOCKING_ERROR_NOT_FATAL)
            goto free_bev_err;
    }

    evb = bufferevent_get_input(bev);
    if (evb == NULL) {
        log_warn("%s Failed to get input buffer", cl->name);
        goto free_bev_err;
    }
    if (evbuffer_enable_locking(evb, NULL) < 0) {
        log_warn("%s Failed to enable locking on input", cl->name);
        if (!LOCKING_ERROR_NOT_FATAL)
            goto free_bev_err;
    }

    bufferevent_setcb(bev, read_cb, NULL, client_event_cb, cl);

    if (bufferevent_socket_connect(bev, (struct sockaddr *)dest, sizeof dest[0]) != 0) {
        log_err("%s Failed to connect", cl->name);
        goto free_bev_err;
    }

    cl->ssl_ctx = ssl_ctx;
    cl->ssl = ssl;
    cl->base = base;
    cl->bev = bev;
    return 0;

free_bev_err:
    bufferevent_free(bev);
    ssl = NULL;
free_base_err:
    event_base_free(base);
free_ssl_err:
    if (ssl != NULL)
        SSL_free(ssl);
free_ctx_err:
    SSL_CTX_free(ssl_ctx);
err:
    ssl_lib_deinit();
    return -1;
}

int ssl_client_run(struct ssl_client * cl)
{
    int err;

    log_info("%s Starting", cl->name);

    bufferevent_enable(cl->bev, EV_READ | EV_WRITE);
    err = event_base_dispatch(cl->base);
    if (err < 0) {
        log_err("%s Failed to dispatch", cl->name);
        goto err;
    } else if (err == 1) {
        log_err("%s Nothing to do !", cl->name);
        goto err;
    }

    log_info("%s Finished", cl->name);
    return 0;

err:
    return -1;
}

void ssl_client_deinit(struct ssl_client * cl)
{
    SSL_set_shutdown(cl->ssl, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(cl->ssl);
    bufferevent_free(cl->bev);
    cl->bev = NULL;
    cl->ssl = NULL;

    SSL_CTX_free(cl->ssl_ctx);
    cl->ssl_ctx = NULL;

    event_base_free(cl->base);
    cl->base = NULL;

    ssl_lib_deinit();
}

int ssl_client_write(struct ssl_client * cl, const char * cmd, const int from_cb)
{
    struct evbuffer * output = bufferevent_get_output(cl->bev);

    if (!from_cb)
        evbuffer_lock(output);

    evbuffer_add_printf(output, "%s\n", cmd);

    if (!from_cb)
        evbuffer_unlock(output);

    return 0;
}

char * ssl_client_read(struct ssl_client * cl, const int from_cb)
{
    struct evbuffer * input = bufferevent_get_output(cl->bev);
    char * cmd;

    if (!from_cb)
        evbuffer_lock(input);

    cmd = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);

    if (!from_cb)
        evbuffer_unlock(input);

    return cmd;
}
