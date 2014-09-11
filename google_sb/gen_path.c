
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/sha.h>

int process(const char *path)
{
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    uint32_t *res = (uint32_t *) sha256;
    SHA256((unsigned char *) path, strlen(path), sha256);
    printf("%s %08x\n", path, *res);
    return 0;
}

/*
 * - Remove all leading and trailing dots.
 * - Replace consecutive dots with a single dot.
 * - If the hostname can be parsed as an IP address, it should be normalized to 4 dot-separated decimal values.
 *   The client should handle any legal IP- address encoding, including octal, hex, and fewer than 4 components.
 * - Lowercase the whole string.
 */
static int canonicalize_hostname(const char *from, const size_t from_len, char *res, const int res_size)
{
    const char *ptr;
    const char *to = from + from_len;
    int i;

    if (from == NULL) {
	res[0] = 0;
	return 0;
    }

    /*
     * skip leading dots
     */
    ptr = from;
    while (*ptr != 0 && ptr < to) {
	if (*ptr != '.')
	    break;
	ptr++;
    }

    /*
     * Copy hostname in lowercase, skipping consecutive dots,
     * port numbers etc.
     */
    i = 0;
    while (*ptr != 0 && ptr < to && *ptr != ':') {

	/* res cant contain the whole hostname */
	if (i >= res_size)
	    return -1;

	/* skip consecutive dots */
	if (*ptr == '.') {
	    while (*(ptr + 1) == '.')
		ptr++;
	}

	res[i] = (char) tolower((int) (*ptr));
	ptr++;
	i++;
    }

    /*
     * Remove trailing dots
     */
    while (i > 0 && res[i - 1] == '.')
	i--;
    /* The hostname contains only a single '.' ? */
    if (i == 0)
	return -1;

    /*
     * Append the final / and 0
     */
    if (i + 1 > res_size)
	return -1;
    res[i++] = 0;

    return i;
}

/*
 * - The sequences "/../" and "/./" in the path should be resolved, by replacing "/./" with "/", and removing "/../" along with the preceding path component.
 * - Runs of consecutive slashes should be replaced with a single slash character.
 */
int canonicalize_path(const char *from, char *res, const size_t res_size)
{
    const char *ptr;
    size_t used;
    size_t previous_used;

    previous_used = 0;
    used = 0;
    ptr = from;
    while (*ptr != 0) {
	const char *start;
	const char *end;
	size_t len;

	while (*ptr == '/')
	    ptr++;
	if (*ptr == 0)
	    break;
	start = ptr;

	while (*ptr != '/' && *ptr != 0)
	    ptr++;
	if (ptr == start)
	    break;
	end = ptr;
	len = end - start;

	/*
	 * If '..' go back to the last saved position
	 */
	if (len == 2 && start[0] == '.' && start[1] == '.' && (*end == 0 || *end == '/')) {
	    used = previous_used;
	    continue;
	}

	previous_used = used;	/* save the current position to get back quicker if '..' is found */

	if (used + len >= res_size)
	    goto err;
	memcpy(res + used, start, len);
	used += len;
	if (*end != 0) {
	    if (used + 1 >= res_size)
		goto err;
	    res[used++] = '/';
	}
    }

    if (used + 1 >= res_size)
	goto err;
    res[used++] = 0;

    return 0;
err:
    return -1;


}

/*
 * from:
 * http://www.example.com/path/file.html
 *
 * to:
 * www.example.com/path/file.html (0x02db21c6)
 * www.example.com/path/ (0x4138f765)
 * www.example.com/ (0xd59cc9d3)
 * example.com/path/file.html (0x02db21c6)
 * example.com/path/ (0x4138f765)
 * example.com/ (0x73d986e0)
 */
int gen_path(const char *orig)
{
    const char *ptr;
    const char *url;
    char *host;
    char *path;
    char *host_ptr;
    const size_t buff_len = strlen(orig) + 2;
    char *buff;
    size_t len;

    buff = calloc(1, buff_len);
    if (buff == NULL)
	goto err;

    /*
     * 1/ url
     */

    /* skip leading space */
    ptr = orig;
    while (isspace(*ptr))
	ptr++;
    /* skip the protocol */
    url = strstr(ptr, "://");
    if (url != NULL)
	url += sizeof "://" - 1;
    else
	url = ptr;

    /*
     * 2/ host
     */
    ptr = strchr(url, '/');
    if (ptr == NULL)
	len = strlen(url);
    else
	len = ptr - url;
    host = calloc(1, len + 1);
    if (host == NULL)
	goto free_buff_err;
    if (canonicalize_hostname(url, len, host, len + 1) < 0)
	goto free_host_err;

    /*
     * 3/ path
     */
    if (ptr != NULL) {		/* ptr points to the 1st / of path */

	/* skip leading / */
	while (*ptr == '/')
	    ptr++;
	if (*ptr == 0)
	    ptr = NULL;
    }

    path = NULL;
    if (ptr != NULL && *ptr != 0) {
	const size_t len = strlen(ptr);

	path = calloc(1, len + 2);	/* one more to save the last '/' if any ... */
	if (path == NULL)
	    goto free_host_err;

	if (canonicalize_path(ptr, path, len + 2) < 0)
	    goto free_path_err;
    }

    /* At this point, host and path are correct */

    host_ptr = host;
    while (*host_ptr != 0) {

	if (path != NULL) {
	    char *path_copy = strdup(path);
	    char *path_end = NULL;

	    for (;;) {

		snprintf(buff, buff_len, "%s/%s%s", host_ptr, path_copy, path_end != NULL ? "/" : "");
		process(buff);

		path_end = strrchr(path_copy, '/');
		if (path_end == NULL || *(path_end + 1) == 0)
		    break;

		*path_end = 0;
	    }

	    free(path_copy);
	}

	snprintf(buff, buff_len, "%s/", host_ptr);
	process(buff);

	host_ptr = strchr(host_ptr, '.');
	if (host_ptr == NULL || strchr(host_ptr + 1, '.') == NULL)
	    break;
	host_ptr++;
    }


    if (path != NULL)
	free(path);
    free(host);
    free(buff);
    return 0;

free_path_err:
    free(path);
free_host_err:
    free(host);
free_buff_err:
    free(buff);
err:
    return -1;
}

int main(int ac, char **av)
{
    int i;

    for (i = 1; i < ac; i++) {
	gen_path(av[i]);

    }




}
