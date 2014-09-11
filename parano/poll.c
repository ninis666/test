
#include <stdio.h>
#include <poll.h>

#define ici() fprintf(stderr, "ici: %s:%d !!!\n", __FILE__, __LINE__)

int main(void)
{
    ici();
    poll(NULL, 0, 4 * 1000);
    ici();

    return 0;

}
