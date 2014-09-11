
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void copy(register short *to, register short *from, const int count)
{
    register int n = (count + 7) / 8;

    switch (count % 8) {
    case 0: do { *to++ = *from++;
    case 7:      *to++ = *from++;
    case 6:      *to++ = *from++;
    case 5:	 *to++ = *from++;
    case 4:	 *to++ = *from++;
    case 3:	 *to++ = *from++;
    case 2:	 *to++ = *from++;
    case 1:	 *to++ = *from++;
	} while (--n > 0);
    }
}

#define COUNT 1024
int main(int ac, char **av)
{
    short * from;
    short * to;
    int count;
    int nloop;
    struct timeval  start, end;
    int i;

    if (ac < 3) {
    usage:
        fprintf(stderr, "Usage : %s <size> <nloop>\n", av[0]);
        return 1;
    }

    count = atoi(av[1]);
    if (count <= 0)
        goto usage;

    nloop = atoi(av[2]);
    if (nloop <= 0)
        goto usage;

    from = malloc(sizeof from[0] * count);
    to = malloc(sizeof to[0] * count);
    if (from == NULL || to == NULL) {
        fprintf(stderr, "malloc failed: %m\n");
        return 1;
    }

    srandom(getpid());

    for (i = 0 ; i < count ; i++)
        from[i] = random() & 0x0FFF;

    gettimeofday(&start, NULL);
    for (i = 0 ; i < nloop ; i++)
        copy(to, from, count);
    gettimeofday(&end, NULL);

    if (memcmp(from, to, count * sizeof from[0]) != 0) {
        fprintf(stderr, "copy failed !\n");
        return 1;
    }

    printf("copy: %dms\n", (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000);

    gettimeofday(&start, NULL);
    for (i = 0 ; i < nloop ; i++)
        memcpy(to, from, count * sizeof from[0]);
    gettimeofday(&end, NULL);

    printf("memcpy: %dms\n", (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000);

    return 0;
}
