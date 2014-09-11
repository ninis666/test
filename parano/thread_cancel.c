
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_THREAD 10

void cleanup(char * str)
{
    printf("%s called from %s\n", __FUNCTION__, str);
}

void work(const char * str)
{
    pthread_cleanup_push(cleanup, __FUNCTION__);

    printf("Working from %s\n", str);

    sleep(1);

    pthread_cleanup_pop(0);
}

void * thread_fun(void * arg)
{
    int n = (long )arg;
    char name[80];

    snprintf(name, sizeof name, "%s_%d", __FUNCTION__, n);

    pthread_cleanup_push(cleanup, name);

    for (;;)
        work(name);

    pthread_cleanup_pop(0);
}

int main(__attribute__((unused))int ac, __attribute__((unused))char **av)
{
    pthread_t tid[MAX_THREAD];
    long i;

    for (i = 0 ; i < (long)(sizeof tid / sizeof tid[0]) ; i++)
        pthread_create(&tid[i], NULL, thread_fun, (void *)i);

    sleep(5);

    for (i = 0 ; i < (long)(sizeof tid / sizeof tid[0]) ; i++)
        pthread_cancel(tid[i]);

    for (i = 0 ; i < (long)(sizeof tid / sizeof tid[0]) ; i++)
        pthread_join(tid[i], NULL);

    return 0;
}
