
#include <stdio.h>
#include <time.h>
#include <openssl/err.h>

#include "event_ssl.h"
#include "logger.h"
#include "xmalloc.h"

static int send_ack(struct ssl_client * cl, const char * cmd)
{
    struct evbuffer * output = bufferevent_get_output(cl->bev);
    char ack[1024];

    snprintf(ack, sizeof ack, "ACK %s", cmd);

    log_info("Tx: <%s>", cmd);
    evbuffer_add_printf(output, "%s\n", cmd);
    return 0;
}

static int client_read(struct ssl_client * cl, struct evbuffer *input)
{
    char * cmd = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    int ret;

    if (cmd != NULL) {
        log_info("Rx: <%s>", cmd);
        ret = send_ack(cl, cmd);
        free(cmd);
    } else
        ret = 0;

    return ret;
}

int main(int ac, char **av)
{
    struct sockaddr_in source;
    struct ssl_server srv;

    logger_init("ssl_server");
    logger_set_drivers_console();
    logger_set_drivers_file();
    logger_remove_drivers_redis();
    logger_remove_drivers_syslog();

    memset(&source, 0, sizeof source);
    source.sin_family = AF_INET;
    source.sin_port = htons(DEFAULT_PORT);

    if (ssl_server_init(&srv, "serv.privkey.pem", "serv.cacert.pem", &source) < 0)
        goto err;
    srv.read_fun = client_read;

    ssl_server_run(&srv);

    return 0;

err:
    return 1;
}
