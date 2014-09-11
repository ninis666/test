
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

void * thread_work(void * arg)
{
    int i;
    const int n = atoi(arg);

    for (i = 0 ; i < n ; i++) {
        fprintf(stderr, "[%d/%d] Working !\n", i + 1, n);
        usleep(100 * 1000);
    }

    fprintf(stderr, "Done\n");

    pthread_join(pthread_self(), NULL);
    return arg;
}

int main(int ac, char **av)
{
    pthread_t tid;
    int i;

    if (ac < 2) {
        fprintf(stderr, "Usage : %s <n>\n", av[0]);
        goto err;
    }

    i = pthread_create(&tid, NULL, thread_work, av[1]);
    if (i != 0) {
        fprintf(stderr, "Failed to create thread : %s", strerror(i));
        goto err;
    }

    pthread_join(tid, NULL);
    sleep(1);
    pthread_join(tid, NULL);
    return 0;

err:
    return 1;
}
