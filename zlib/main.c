
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <zlib.h>

static ssize_t do_read(int fd, void * data, const size_t size)
{
    size_t done;
    uint8_t * buff = data;

    done = 0;
    while (done < size) {
        size_t n;

        n = read(fd, buff + done, size - done);
        if (n < 0) {
            fprintf(stderr, "Failed to read : %s\n", strerror(errno));
            return -1;
        }

        if (n == 0)
            break;
        done += n;
    }

    return (ssize_t )done;
}

static inline char * string_read(int fd)
{
    char * str = NULL;
    size_t used;
    size_t allocated;

    used = 0;
    allocated = 0;
    for (;;) {
        size_t n;
        char c;

        n = do_read(fd, &c, sizeof c);
        if (n < 0)
            goto err;
        if (n != sizeof c) {
            fprintf(stderr, "Unexpected EOF\n");
            break;
        }

        while (used + 1 >= allocated) {
            char * tmp;

            tmp = realloc(str, allocated + 16);
            if (tmp == NULL) {
                fprintf(stderr, "Failed to extend string : %s\n", strerror(errno));
                goto err;
            }

            str = tmp;
            allocated += 16;
        }

        str[used ++] = c;
        if (c == 0)
            break;
    }

    return str;

err:
    if (str != NULL)
        free(str);
    return NULL;
}

static inline int do_skip(int fd, const off_t offset)
{
    off_t done;

    if (fd != STDIN_FILENO) {

        done = lseek(fd, offset, SEEK_CUR);
        if (done < 0) {
            fprintf(stderr, "Failed to skip <%ldb> : %s\n", offset, strerror(errno));
            return -1;
        }
    } else {
        uint8_t b;

        for (done = 0 ; done < offset ; done ++) {
            ssize_t n;

            n = do_read(fd, &b, sizeof b);
            if (n < 0)
                return -1;
            if (n == 0)
                break;
        }
    }

    if (done != offset) {
        fprintf(stderr, "Failed to skip : <%ld> asked, got <%ld>\n", offset, done);
        return -1;
    }

    return 0;
}

#define GZ_MAGIC       ((uint16_t )(0x1F | (0x8B << 8)))
#define GZ_METHOD      ((uint8_t )8)
#define GZ_FLG_HCRC    (1 << 1)
#define GZ_FLG_EXTRA   (1 << 2)
#define GZ_FLG_NAME    (1 << 3)
#define GZ_FLG_COMMENT (1 << 4)

/*
 * http://www.gzip.org/zlib/rfc-gzip.html
 *
 * +---+---+---+---+---+---+---+---+---+---+
 * |ID1|ID2|CM |FLG|     MTIME     |XFL|OS |
 * +---+---+---+---+---+---+---+---+---+---+
 *
 * FLG (FLaGs)
 *   bit 1   FHCRC
 *   bit 2   FEXTRA
 *   bit 3   FNAME
 *   bit 4   FCOMMENT
 *
 */
int skip_header(int fd)
{
    uint16_t id;
    uint8_t cm;
    uint8_t flg;
    uint32_t mtime;
    uint8_t xfl;
    uint8_t os;
#define safe_read(fd, data) do { \
        const ssize_t __s__ = do_read(fd, (data), sizeof (data)[0]);    \
        if (__s__ < 0)                                                  \
            return -1;                                                  \
                                                                        \
        if (__s__ != sizeof (data)[0]) {                                \
            fprintf(stderr, "Failed to read <%zdb>, only <%zdb> done", sizeof (data)[0], __s__); \
            goto err;                                                   \
        }                                                               \
    } while (0)

    safe_read(fd, &id);
    safe_read(fd, &cm);
    safe_read(fd, &flg);
    safe_read(fd, &mtime);
    safe_read(fd, &xfl);
    safe_read(fd, &os);

    if (id != GZ_MAGIC) {
        fprintf(stderr, "Invalid magic ID, <%#x> expected, <%#x> found\n", GZ_MAGIC, id);
        goto err;
    }

    if (cm != GZ_METHOD) {
        fprintf(stderr, "Invalid compression method, <%#x> expected, <%#x> found\n", GZ_METHOD, cm);
        goto err;
    }

    if (flg & GZ_FLG_EXTRA) {
        uint16_t xlen;

        safe_read(fd, &xlen);
        if (do_skip(fd, xlen) < 0)
            goto err;
    }

    if (flg & GZ_FLG_NAME) {
        char * file;

        file = string_read(fd);
        if (file == NULL)
            goto err;

        fprintf(stderr, "filename <%s>\n", file);
        free(file);
    }

    if (flg & GZ_FLG_COMMENT) {
        char * comment;

        comment = string_read(fd);
        if (comment == NULL)
            goto err;

        fprintf(stderr, "comment <%s>\n", comment);
        free(comment);
    }

    if (flg & GZ_FLG_HCRC) {
        if (do_skip(fd, sizeof(uint16_t)) < 0)
            goto err;
    }

    return 0;

err:
    return -1;
}

struct gz_input {
    unsigned char data[16384];
    int fd;
};

static unsigned int gunzip_input(void * arg, z_const unsigned char **res)
{
    struct gz_input * f = arg;
    unsigned int done;

    done = 0;
    while (done < sizeof f->data) {
        ssize_t n;

        n = read(f->fd, f->data + done, sizeof f->data - done);
        if (n < 0) {
            done = 0;
            fprintf(stderr, "Failed to read : %s\n", strerror(errno));
            break;
        }

        if (n == 0)
            break;

        done += n;
    }

    *res = f->data;
    return done;
}

struct gz_output {
    uint32_t crc;
    uint32_t total;
    int fd;
};

static int gunzip_output(void * arg, unsigned char * data, unsigned int size)
{
    unsigned int done;
    struct gz_output * f = arg;

    done = 0;
    while (done < size) {
        ssize_t n;

        n = write(f->fd, data + done, size - done);
        if (n < 0) {
            const int err = (errno != 0) ? errno : -1;
            fprintf(stderr, "Failed to write : %s\n", strerror(errno));
            return err;
        }

        done += n;
    }

    f->crc = crc32(f->crc, data, size);
    f->total += size;
    return 0;
}

#define GZ_WINDOW_BITS 15
#define GZ_WINDOW_SIZE (1 << GZ_WINDOW_BITS)
static int gunzip_fd(int source, int dest)
{
    int ret;
    z_stream strm;
    struct gz_input input;
    struct gz_output output;
    unsigned char * window;
    uint32_t crc;
    uint32_t total;

    memset(&input, 0, sizeof input);
    input.fd = source;

    memset(&output, 0, sizeof output);
    output.fd = dest;
    output.crc = crc32(0L, Z_NULL, 0);
    output.total = 0;

    window = malloc(GZ_WINDOW_SIZE);
    if (window == NULL) {
        fprintf(stderr, "Failed to allocate window of <%db> : %s\n", GZ_WINDOW_SIZE, strerror(errno));
        goto err;
    }

    memset(&strm, 0, sizeof strm);
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = inflateBackInit(&strm, GZ_WINDOW_BITS, window);
    if (ret != Z_OK) {
        fprintf(stderr, "Failed to initialize zlib : %s\n", zError(ret));
        goto free_err;
    }

    ret = inflateBack(&strm, gunzip_input, &input, gunzip_output, &output);
    if (ret != Z_STREAM_END) {
        fprintf(stderr, "Failed to decompress : %s\n", zError(ret));
        goto free_err;
    }

    if (strm.avail_in >= sizeof crc) {

        memcpy(&crc, strm.next_in, sizeof crc);

        if (crc != output.crc) {
            fprintf(stderr, "crc missmatch (<%#x> expected, <%#x> found)\n", crc, output.crc);
            goto free_err;
        }

        strm.next_in += sizeof crc;
        strm.avail_in -= sizeof crc;
    }

    if (strm.avail_in >= sizeof total) {

        memcpy(&total, strm.next_in, sizeof total);

        if (total != output.total) {
            fprintf(stderr, "crc missmatch (<%u> expected, <%u> found)\n", total, output.total);
            goto free_err;
        }

        strm.next_in += sizeof total;
        strm.avail_in -= sizeof total;
    }

    /* clean up and return */
    inflateEnd(&strm);
    return 0;

free_err:
    inflateEnd(&strm);
err:
    return -1;
}

int main(int ac, char **av)
{
    int input;
    int output;

    if (ac < 2)
        input = STDIN_FILENO;
    else {
        input = open(av[1], O_RDONLY);
        if (input < 0) {
            fprintf(stderr, "Failed to open <%s> : %s\n", av[1], strerror(errno));
            return 1;
        }
    }

    if (ac < 3)
        output = STDOUT_FILENO;
    else {
        output = open(av[2], O_CREAT | O_WRONLY, 0644);
        if (output < 0) {
            fprintf(stderr, "Failed to create <%s> : %s\n", av[1], strerror(errno));
            return 1;
        }
    }

    skip_header(input);
    gunzip_fd(input, output);

    close(input);
    close(output);
    return 0;
}
