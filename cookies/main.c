
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <curl/curl.h>

__attribute__ ((__format__ (__printf__, 2, 3))) static void do_log(FILE * stream, const char * fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    vfprintf(stream, fmt, va);
    va_end(va);
    fprintf(stream, "\n");
    fflush(stream);
}
# define log_err(...) do_log(stderr,  "ERROR " __VA_ARGS__)
# define log_info(...) do_log(stdout, __VA_ARGS__)

struct buffer {
    size_t size;
    size_t used;
    char * data;
};
#define BUFFER_BLOCK_SIZE 4096

static int buffer_init(struct buffer * buffer)
{
    memset(buffer, 0, sizeof buffer[0]);
    return 0;
}

static void buffer_free(struct buffer * buffer)
{
    if (buffer->data != NULL)
        free(buffer->data);
    memset(buffer, 0, sizeof buffer[0]);
}

static int buffer_add(struct buffer * buffer, const void * data, const size_t size)
{
    while (buffer->size < buffer->used + size) {
        char * tmp;

        tmp = realloc(buffer->data, buffer->size + BUFFER_BLOCK_SIZE);
        if (tmp == NULL) {
            log_err("Failed to extend buffer from <%zd> to <%zd>", buffer->size, buffer->size + BUFFER_BLOCK_SIZE);
            goto err;
        }

        buffer->data = tmp;
        buffer->size += BUFFER_BLOCK_SIZE;
    }

    memcpy(buffer->data + buffer->used, data, size);
    buffer->used += size;
    return 0;

err:
    return -1;
}

static size_t write_wrapper(char *data, size_t size, size_t nmemb, void * private)
{
    struct buffer * buffer = private;
    const size_t s = size * nmemb;

    if (buffer_add(buffer, data, s) < 0)
        return 0;

    return s;
}

static int debug_wrapper(__attribute__((unused)) CURL * curl, curl_infotype type, char * msg, size_t size, __attribute__((unused)) void * private)
{
    char * str = NULL;
    char * ptr;
    size_t used;
    size_t n;

    switch (type) {
    default:
        log_info("%d: Unknown type", type);
        break;

    case CURLINFO_DATA_IN:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
    case CURLINFO_SSL_DATA_OUT:
        str = malloc(size * 2 + 1);
        *str = 0;
        used = 0;
        for (n = 0 ; n < size ; n++) {
            int i;

            i = snprintf(str, (size * 2 + 1) - used, "%02x", msg[n]);
            if ((size_t)i >= (size * 2 + 1) - used)
                break;
            used += (size_t)i;
        }
        break;

    case CURLINFO_TEXT:
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
        str = strndup(msg, size);
        while ((ptr = strchr(str, '\n')) != NULL)
            *ptr = 0;
        while ((ptr = strchr(str, '\r')) != NULL)
            *ptr = 0;
        break;
    }

    if (str != NULL) {
        log_info("%d : <%s>", type, str);
        free(str);
    }

    return 0;
}

static int print_cookies(const char * fmt, CURL * curl)
{
    CURLcode res;
    struct curl_slist *cookies;
    struct curl_slist *nc;
    int i;

    printf("%s\n", fmt);
    res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if (res != CURLE_OK) {
        fprintf(stderr, "Curl curl_easy_getinfo failed: %s\n", curl_easy_strerror(res));
        return -1;
    }

    for (i = 0, nc = cookies ; nc != NULL ; nc = nc->next, i++)
        printf("[%d]: %s\n", i, nc->data);

    if (i == 0)
        printf("(none)\n");
    curl_slist_free_all(cookies);

    return 0;
}

__attribute__((unused)) static void print_buffer(struct buffer * buffer)
{
    if (buffer->data[buffer->used - 1] != 0) {
        const char zero = 0;
        buffer_add(buffer, &zero, sizeof zero);
    }

    log_info("Rx: <%s>", buffer->data);
}

int main(__attribute__((unused)) int ac, __attribute__((unused)) char **av)
{
    int res;
    CURL * curl;
    struct buffer buffer;
    const char * url = ac < 2 ? "http://www.enhanceie.com/test/cookie/" : av[1];

    res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != 0) {
        log_err("Failed to init curl");
        goto err;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        log_err("Failed to get a new curl_easy object");
        goto global_free_err;
    }

    buffer_init(&buffer);

#define __curl_easy_setopt(...) do {                                    \
        res = curl_easy_setopt(__VA_ARGS__);                            \
        if (res != 0) {                                                 \
            log_err("curl_easy_setopt(" # __VA_ARGS__ ") Failed : %s", curl_easy_strerror(res)); \
            goto curl_free_err;                                         \
        }                                                               \
        log_info("curl_easy_setopt(" # __VA_ARGS__ ") : Ok");           \
    } while (0)

    __curl_easy_setopt(curl, CURLOPT_URL, url);
    __curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    __curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); /* just to start the cookie engine */
    //__curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "/tmp/prout.cookiejar"); /* just to start the cookie engine */
    __curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_wrapper);
    __curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    __curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_wrapper);

    log_info("Curl initialized");

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Curl perform failed: %s\n", curl_easy_strerror(res));
        goto curl_free_err;
    }

    //print_buffer(&buffer);
    print_cookies("After 1st get:", curl);
    buffer_free(&buffer);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Curl perform failed: %s\n", curl_easy_strerror(res));
        goto curl_free_err;
    }

    print_cookies("After 2nd get:", curl);



    buffer_free(&buffer);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;

curl_free_err:
    curl_easy_cleanup(curl);
    buffer_free(&buffer);
global_free_err:
    curl_global_cleanup();
err:
    return 1;
}
