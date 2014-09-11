
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "ssl.h"

#define CA_CERTIFICATE  "client.cacert.pem"
#define PRIVATE_KEY     "client.privkey.pem"

#define HOST_ADDR "127.0.0.1"
#define HOST_PORT 1111

int main(int ac, char **av)
{
    struct ssl_client cl;
    struct in_addr local_addr;
    int local_port;
    struct in_addr host_addr;
    int host_port;
    int i;
    int input;
    int output;

    ssl_client_set_default(&cl);

    local_addr.s_addr = INADDR_ANY;
    local_port = 0;

    inet_aton(HOST_ADDR, &host_addr);
    host_port = HOST_PORT;

    input = STDIN_FILENO;
    output = STDOUT_FILENO;

    for (i = 1 ; i < ac ; i++) {

        if (strcmp(av[i], "-local_addr") == 0) {

            if (i + 1 >= ac)
                goto no_arg;
            if (inet_aton(av[i + 1], &local_addr) == 0)
                goto inv_arg;
            i++;

        } else if (strcmp(av[i], "-local_port") == 0) {

            if (i + 1 >= ac)
                goto no_arg;
            local_port = atoi(av[i + 1]);
            if (local_port < 0 || local_port >= UINT16_MAX)
                goto inv_arg;
            i++;

        } else if (strcmp(av[i], "-host_addr") == 0) {

            if (i + 1 >= ac)
                goto no_arg;
            if (inet_aton(av[i + 1], &host_addr) == 0)
                goto inv_arg;
            i++;

        } else if (strcmp(av[i], "-host_port") == 0) {

            if (i + 1 >= ac)
                goto no_arg;
            host_port = atoi(av[i + 1]);
            if (host_port < 0 || host_port >= UINT16_MAX)
                goto inv_arg;
            i++;

        } else if (strcmp(av[i], "-input") == 0) {

            if (i + 1 >= ac)
                goto no_arg;

            input = open(av[i + 1], O_RDONLY);
            if (input < 0) {
                fprintf(stderr, "Failed to open <%s> : %s\n", av[i + 1], strerror(errno));
                goto usage;
            }

        } else if (strcmp(av[i], "-output") == 0) {

            if (i + 1 >= ac)
                goto no_arg;

            output = open(av[i + 1], O_CREAT | O_TRUNC | O_WRONLY, 0664);
            if (output < 0)
                goto inv_arg;

        } else if (strcmp(av[i], "-help") == 0)
            goto usage;

        continue;

    inv_arg:
        fprintf(stderr, "Invalid argument for <%s> option : <%s>\n", av[i], av[i + 1]);
        goto usage;

    no_arg:
        fprintf(stderr, "No valid argument for <%s> option\n", av[i]);
    usage:
        fprintf(stderr, "Usage: %s [-local_addr <addr>] [-local_port <port>] [-host_addr <addr>] [-host_port <port>] [-input <file>][-help]\n", av[0]);
        return 1;
    }

    if (ssl_client_init(&cl, CA_CERTIFICATE, SSL_FILETYPE_PEM, PRIVATE_KEY, SSL_FILETYPE_PEM, local_addr, local_port, host_addr, host_port, 0) < 0)
        goto err;

    if (isatty(input))
        printf("Triming EOL\n");

    for (;;) {
        char buffer[4096 + 1];
        int size;
        int got;

        size = read(input, buffer, sizeof buffer - 1);
        if (size < 0) {
            fprintf(stderr, "Failed to read from stdin : %s\n", strerror(errno));
            break;
        }
        if (size == 0)
            break;

        if (isatty(input)) {
            while (size > 0 && buffer[size - 1] == '\n')
                buffer[--size] = 0;
            if (size == 0)
                continue;
            buffer[size] = 0;
            size ++;
        }

        if (ssl_client_write(&cl, buffer, size) <= 0)
            goto close_err;

        got = 0;
        while (got < size) {

            i = ssl_client_read(&cl, buffer, sizeof buffer);
            if (i <= 0)
                goto close_err;

            write(output, buffer, i);
            got += i;
        }
    }

    ssl_client_free(&cl);
    return 0;

close_err:
    ssl_client_free(&cl);
err:
    return 1;
}
