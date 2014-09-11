
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>

#define TIMEVAL_TO_MS(tv) ((tv)->tv_sec * 1000 + (tv)->tv_usec / 1000)

typedef int (*my_exec_cb_t) (void *private, const void *data, const size_t data_size);

int my_exec(const char *cmdline, const long timeout_ms, my_exec_cb_t stdout_cb, my_exec_cb_t stderr_cb, void *private)
{
    int out[2];
    int err[2];
    pid_t pid;
    enum {
        idx_stdout,
        idx_stderr,
        idx_max,
    };
    struct pollfd fds[idx_max];
    struct timeval start;
    char *cmd;
    char *ptr;
    char *token;
    char **argv;
    int argc;
    int status;

    cmd = strdup(cmdline);
    if (cmd == NULL) {
        fprintf(stderr, "exec: <%s> Failed to duplicate cmdline : %s\n", cmdline, strerror(errno));
        goto err;
    }

    argv = calloc(2, sizeof argv[0] * 2);
    if (argv == NULL) {
        fprintf(stderr, "exec: <%s> Failed to allocate argv : %s\n", cmdline, strerror(errno));
        goto free_cmd_err;
    }

    token = strtok_r(cmd, " \n", &ptr);
    argv[0] = token;
    argv[1] = strrchr(token, '/');
    if (argv[1] == NULL)
        argv[1] = token;
    else
        argv[1] = argv[1] + 1;
    argc = 2;

    for (;;) {
        char **tmp;

        token = strtok_r(NULL, " \n", &ptr);
        if (token == NULL)
            break;

        tmp = realloc(argv, sizeof argv[0] * (argc + 2));
        if (tmp == NULL) {
            fprintf(stderr, "exec: <%s> Failed to extend argv : %s\n", cmdline, strerror(errno));
            goto free_argv_err;
        }
        argv = tmp;

        argv[argc] = token;
        argv[argc + 1] = NULL;
        argc++;
    }

    if (pipe(out) < 0) {
        fprintf(stderr, "exec: <%s> Failed to create stdout pipe : %s\n", cmdline, strerror(errno));
        goto free_argv_err;
    }

    if (pipe(err) < 0) {
        fprintf(stderr, "exec: <%s> Failed to create stdout pipe : %s\n", cmdline, strerror(errno));
        goto close_out_err;
    }

    gettimeofday(&start, NULL);

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "exec: <%s> Failed to fork : %s\n", cmdline, strerror(errno));
        goto close_err_err;
    }

    if (pid == 0) {

        close(out[0]);
        if (out[1] != STDOUT_FILENO) {
            dup2(out[1], STDOUT_FILENO);
            close(out[1]);
        }

        close(err[0]);
        if (err[1] != STDERR_FILENO) {
            dup2(err[1], STDERR_FILENO);
            close(err[1]);
        }

        execvp(argv[0], argv + 1);
        fprintf(stderr, "exec: <%s> Failed to execute <%s> : %s\n", cmdline, argv[0], strerror(errno));
        exit(127);
    }

    close(out[1]);
    out[1] = -1;
    close(err[1]);
    err[1] = -1;

    fds[idx_stdout].fd = out[0];
    fds[idx_stderr].fd = err[0];
    fds[idx_stdout].events = fds[idx_stderr].events = POLLIN | POLLERR;
    fds[idx_stdout].revents = fds[idx_stderr].revents = 0;

    for (;;) {
        int i, n;
        size_t idx;

        i = waitpid(pid, &status, WNOHANG);
        if (i < 0) {
            fprintf(stderr, "exec: <%s> Failed to wait pid <%d> : %s\n", cmdline, pid, strerror(errno));
            goto kill_err;
        }
        if (i != 0) {

            if (WIFEXITED(status)) {
                status = WEXITSTATUS(status);
                fprintf(stderr, "exec: <%s> Exited with <%d> retcode\n", cmdline, status);
                break;
            }

            if (WIFSIGNALED(status))
                fprintf(stderr, "exec: <%s> killed by SIG%d%s\n", cmdline, WTERMSIG(status),
                        WCOREDUMP(status) ? " with coredump" : "");
            else if (WIFSTOPPED(status))
                fprintf(stderr, "exec: <%s> stopped by SIG%d%s\n", cmdline, WSTOPSIG(status),
                        WCOREDUMP(status) ? " with coredump" : "");
            else if (WIFCONTINUED(status))
                fprintf(stderr, "exec: <%s> continued\n", cmdline);
            else
                fprintf(stderr, "exec: <%s> Unknown exit status <%d>\n", cmdline, status);
            goto close_err_err;
        }

        if (timeout_ms > 0) {
            struct timeval now;
            gettimeofday(&now, NULL);

            if ((TIMEVAL_TO_MS(&now) - TIMEVAL_TO_MS(&start)) >= timeout_ms) {
                fprintf(stderr, "exec: <%s> Cmd didnt finished within <%ldms>\n", cmdline, timeout_ms);
                goto kill_err;
            }
        }

        n = poll(fds, 2, 1);
        if (n < 0) {
            fprintf(stderr, "exec: <%s> Failed to poll : %s\n", cmdline, strerror(errno));
            goto kill_err;
        }

        if (n == 0)
            continue;

        for (idx = 0, i = 0; idx < idx_max && i < n; idx++) {
            char line[4096];
            ssize_t size;
            int ret;

            if (fds[idx].revents == 0)
                continue;
            i++;
            fds[idx].revents = 0;

            size = read(fds[idx].fd, line, sizeof line);
            if (size < 0) {
                fprintf(stderr, "exec: <%s> Failed to read cmd output : %s\n", cmdline, strerror(errno));
                goto kill_err;
            }

            if (size == 0) {
                fprintf(stderr, "exec: <%s> PID <%d> hanged out\n", cmdline, pid);
                break;
            }

            ret = 0;
            switch (idx) {
                case idx_stdout:
                    if (stdout_cb != NULL)
                        ret = stdout_cb(private, line, (size_t) size);
                    break;

                case idx_stderr:
                    if (stderr_cb != NULL)
                        ret = stderr_cb(private, line, (size_t) size);
                    break;
            }

            if (ret < 0) {
                fprintf(stderr, "exec: <%s> callback failed\n", cmdline);
                goto kill_err;
            }
        }
    }

    close(out[0]);
    close(err[0]);
    free(argv);
    free(cmd);
    return status;

kill_err:
    if (kill(pid, SIGKILL) < 0)
        fprintf(stderr, "exec: <%s> Failed to kill PID <%d> : %s\n", cmdline, pid, strerror(errno));
    else if (waitpid(pid, NULL, 0) < 0)
        fprintf(stderr, "exec: <%s> Failed to wait PID <%d> after killing it : %s\n", cmdline, pid, strerror(errno));
close_err_err:
    close(err[0]);
    if (err[1] >= 0)
        close(err[1]);
close_out_err:
    close(out[0]);
    if (out[1] >= 0)
        close(out[1]);
free_argv_err:
    if (argv != NULL)
        free(argv);
free_cmd_err:
    free(cmd);
err:
    return -1;
}

int stdout_cb(void *private, const void *data, const size_t data_size)
{
    const char *str = private;
    printf("%s: [%s] %p %zd\n", str, __FUNCTION__, data, data_size);
    return 0;
}

int stderr_cb(void *private, const void *data, const size_t data_size)
{
    const char *str = private;
    printf("%s: [%s] %p %zd\n", str, __FUNCTION__, data, data_size);
    return 0;
}

int main(int ac, char **av)
{
    int i;

    for (i = 1; i < ac; i++)
        my_exec(av[i], 5 * 1000, stdout_cb, stderr_cb, av[0]);

    return 0;
}
