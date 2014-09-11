
#include <stdio.h>
#include <unistd.h>

int main(__attribute__((unused)) int ac, __attribute__((unused)) char **av)
{

    for (;;) {
        char line[80];
        ssize_t s;

        pause();
        fprintf(stderr, "Wake up !\n");

        s = read(STDIN_FILENO, line, sizeof line);
        if (s < 0) {
            fprintf(stderr, "Failed to read from stdin : %m\n");
            break;
        }
        if (s == 0)
            break;
    }

    return 0;
}
