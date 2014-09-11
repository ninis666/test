
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <arpa/inet.h>
#include "ssl.h"

#define CA_CERTIFICATE  "serv.cacert.pem"
#define PRIVATE_KEY     "serv.privkey.pem"
#define LOCAL_PORT 1111

int main(int ac, char **av)
{
    struct ssl_serv serv;
    struct ssl_cnx * cnx;
    const struct in_addr local_addr = { INADDR_ANY };
    int i;
    time_t timeout;
    int local_port;

    local_port = LOCAL_PORT;
    timeout = 0;
    for (i = 1 ; i < ac ; i++) {
        if (strcmp(av[i], "-timeout") == 0) {
            if (i + 1 >= ac)
                goto no_arg;
            timeout = time(NULL) + atoi(av[i + 1]);
            i++;

        } else if (strcmp(av[i], "-port") == 0) {
            if (i + 1 >= ac)
                goto no_arg;
            local_port = atoi(av[i + 1]);
            i++;

        } else if (strcmp(av[i], "-help") == 0)
            goto usage;

        continue;

    no_arg:
        fprintf(stderr, "No argument for <%s> option\n", av[i]);
    usage:
        fprintf(stderr, "Usage: %s [-timeout <seconds>] [-port <local_port>] [-help]\n", av[0]);
        return 1;
    }

    if (ssl_serv_init(&serv, CA_CERTIFICATE, SSL_FILETYPE_PEM, PRIVATE_KEY, SSL_FILETYPE_PEM, local_addr, local_port) < 0)
        goto err;

    for (;;) {
        int ret;
        char buffer[4096];

        if (timeout > 0 && time(NULL) >= timeout) {
            printf("Times up !\n");
            break;
        }

        ret = ssl_serv_accept(&serv, 1, &cnx);
        if (ret < 0)
            goto close_srv_err;

        if (ret == 0) {
            usleep(100 * 1000);
            continue;
        }

        for (;;) {
            int size;

            size = ssl_cnx_read(&serv, cnx, buffer, sizeof buffer);
            if (size <= 0)
                break;

            if (ssl_cnx_write(&serv, cnx, buffer, size) <= 0)
                break;
        }

        ssl_cnx_free(&serv, cnx);
    }

    ssl_serv_free(&serv);
    ERR_free_strings();
    return 0;

close_srv_err:
    ssl_serv_free(&serv);
err:
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    return 1;
}
