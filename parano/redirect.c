
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main_child(int __attribute__((unused)) ac, char **av)
{
    char hdr[80];
    const char * bin = strrchr(av[0], '/');
    snprintf(hdr, sizeof hdr, "%s[%d]", (bin != NULL) ? (bin + 1) : av[0], getpid());

    printf("%s: Starting\n", hdr);
    fprintf(stderr, "%s: This is an error\n", hdr);

    printf("%s: Done\n", hdr);
    return 0;
}

int main_mother(int __attribute__((unused)) ac, char **av)
{
    char hdr[80];
    int fd[2];
    pid_t pid;
    const char * bin = strrchr(av[0], '/');

    snprintf(hdr, sizeof hdr, "%s[%d]", (bin != NULL) ? (bin + 1) : av[0], getpid());

    printf("%s: Starting\n", hdr);

    if (pipe(fd) < 0) {
        fprintf(stderr, "%s: Failed to get stdout pipe : %m\n", hdr);
        goto err;
    }

#ifdef F_GETPIPE_SZ
    printf("%s: pipe_in = <%d>, pipe_out = <%d>\n", hdr, fcntl(fd[0], F_GETPIPE_SZ), fcntl(fd[1], F_GETPIPE_SZ));
#endif


    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: Failed to fork : %m\n", hdr);
        goto close_err;
    }

    if (pid == 0) {
        close(fd[0]);

        if (dup2(fd[1], STDOUT_FILENO) < 0)
            fprintf(stderr, "%s: Failed to set STDOUT_FILENO to pipe : %m\n", hdr);

        if (dup2(fd[1], STDERR_FILENO) < 0)
            fprintf(stderr, "%s: Failed to set STDERR_FILENO to pipe : %m\n", hdr);

        execl("./"CHILD_NAME, "./"CHILD_NAME, NULL);
        fprintf(stderr, "%s: Failed to execute <%s> : %m\n", hdr, CHILD_NAME);
        close(fd[1]);
        goto err;
    }

    close(fd[1]);
    for (;;) {
        char buff[1024];
        ssize_t s;

        s = read(fd[0], buff, sizeof buff - 1);
        if (s < 0) {
            fprintf(stderr, "%s: Failed to read from child : %m\n", hdr);
            goto close_err;
        }

        if (s == 0)
            break;
        buff[s] = 0;

        printf("%s: stdout <%s>\n", hdr, buff);
    }

    close(fd[0]);
    close(fd[1]);
    return 0;

close_err:
    close(fd[0]);
    close(fd[1]);
err:
    return EXIT_FAILURE;
}

int main(int ac, char **av)
{
    char * bin;

    bin = strrchr(av[0], '/');
    if (bin == NULL)
        bin = av[0];
    else
        bin ++;

    if (strcmp(bin, CHILD_NAME) == 0)
        exit(main_child(ac, av));

    if (strcmp(bin, MOTHER_NAME) == 0)
        exit(main_mother(ac, av));

    fprintf(stderr, "<%s> should be <mother> or <child>\n", bin);
    return 1;
}
