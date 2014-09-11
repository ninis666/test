
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    struct timeval now;

    for (;;) {
        char tmbuf[80];

        gettimeofday(&now, NULL);

        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", localtime(&now.tv_sec));
        printf("localtime: %s:%ld\n", tmbuf, now.tv_usec / 1000);

        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", gmtime(&now.tv_sec));
        printf("gmtime   : %s:%ld\n", tmbuf, now.tv_usec / 1000);

        usleep(500 * 1000);
    }

    return 0;
}
