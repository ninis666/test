
#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "event_ssl.h"
#include "logger.h"
#include "xmalloc.h"

static int connected_status = 0;
static pthread_mutex_t connected_lock = PTHREAD_MUTEX_INITIALIZER;

static int send_hello(struct ssl_client * cl, const char * from, const int from_cb)
{
    char cmd[1024];
    int n;
    static int seq = 0;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&lock);
    n = seq ++;
    pthread_mutex_unlock(&lock);

    snprintf(cmd, sizeof cmd, "HELLO_%s_%d", from, n);

    log_info("Tx: <%s>", cmd);

    return ssl_client_write(cl, cmd, from_cb);
}

static int client_connect(struct ssl_client * cl)
{
    connected_status ++;
    return send_hello(cl, __FUNCTION__, true);
}

static int read_ack(struct ssl_client * cl, struct evbuffer *input)
{
    char * cmd;

    cmd = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);

    if (cmd != NULL) {
        log_info("Rx: <%s>", cmd);
        free(cmd);
    }

    return send_hello(cl, __FUNCTION__, true);
}

static void * client_main_loop(void * arg)
{
    struct ssl_client  * cl = arg;

    if (ssl_client_run(cl) < 0)
        goto err;

err:
    return arg;
}

int main(int ac, char **av)
{
    struct sockaddr_in dest;
    struct ssl_client cl;
    pthread_t tid;

    logger_init("ssl_client");
    logger_set_drivers_console();
    logger_set_drivers_file();
    logger_remove_drivers_redis();
    logger_remove_drivers_syslog();

    memset(&dest, 0, sizeof dest);
    dest.sin_family = AF_INET;
    inet_aton(DEFAULT_HOST, &dest.sin_addr);
    dest.sin_port = htons(DEFAULT_PORT);

    if (ssl_client_init(&cl, &dest) < 0)
        goto err;
    cl.connected_fun = client_connect;
    cl.read_fun = read_ack;

    if (pthread_create(&tid, NULL, client_main_loop, &cl) != 0) {
        log_warn("Failed to start thread");
        goto deinit_err;
    }

    for (;;) {
        int done;

        if (pthread_tryjoin_np(tid, NULL) == 0)
            goto deinit_err;

        sleep(1);

        pthread_mutex_lock(&connected_lock);
        done = connected_status;
        pthread_mutex_unlock(&connected_lock);

        if (done)
            break;
    }

    while (pthread_tryjoin_np(tid, NULL)) {
        if (send_hello(&cl, __FUNCTION__, false) < 0)
            break;
        //usleep(100 * 1000);
    }

    ssl_client_deinit(&cl);
    logger_free();
    return 0;


deinit_err:
    ssl_client_deinit(&cl);
err:
    logger_free();
    return 1;
}
