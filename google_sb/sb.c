
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sb.c 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define PFX "[SB] "
#include "logger.h"
#include "httpreq.h"
#include "buffer.h"
#include "rwlock.h"
#include "sbdb.h"
#include "sb.h"
#include "sbcache.h"

static int debug = 0;

static size_t write_to_mem(char *data, size_t size, size_t nmemb, void *dest)
{
    tbuffer *buffer = dest;

    if (buffer_append(buffer, (unsigned char *) data, size * nmemb) != STATUS_SUCCESS) {
	log_crit("Can't append to buffer");
	return 0;
    }

    return size * nmemb;
}

static inline size_t sb_make_cmd(char *res, const size_t size, const char *cmd, const char *url)
{
    size_t used;

    used = (size_t) snprintf(res, size, "%s/%s?", url, cmd);
    if (used >= size) {
	log_crit("Can't append <%s>", cmd);
	return 0;
    }

    return used;
}

static int make_header(char *res, const int size, const char *client, const char *key, const char *appver, const char *pver)
{
    int used;

    used = snprintf(res, (size_t) size, "client=%s&apikey=%s&appver=%s&pver=%s", client, key, appver, pver);
    if (used >= size) {
	log_crit("Can't append header");
	return 0;
    }

    return used;
}

static int do_http_get(thttpreq_ctx * http, const char *url, tbuffer * buffer, const int is_string)
{
    thttpreq *cmd;
    int i;
    int ret_code;
    unsigned char zero = 0;

    buffer_reset(buffer);

    cmd = httpreq_create();
    if (cmd == NULL) {
	log_err("Can't create http request");
	goto err;
    }

    i = httpreq_set_url(cmd, (char *) url);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP req url: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_set_method(cmd, HTTPREQ_METHOD_GET);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP get method: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_set_write_mem_func(cmd, write_to_mem, buffer);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP callback: %s", status_to_str(i));
	goto free_req_err;
    }

    if (debug)
	log_debug("HTTP GET <%s>", url);

    i = httpreq_perform(cmd);
    if (i != STATUS_SUCCESS) {
	log_err("Can't HTTP execute command: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_get_status(cmd, &ret_code, NULL);
    if (i != STATUS_SUCCESS) {
	log_err("Can't get HTTP status: %s", status_to_str(i));
	goto free_req_err;
    }

    httpreq_free(cmd);

    if (ret_code != 200) {
	log_err("HTTP GET <%s>: error <%d>", url, ret_code);
	goto free_buffer_err;
    }

    if (is_string && buffer->buf_size > 0 && buffer->buf[buffer->buf_size - 1] != 0) {
	i = buffer_append(buffer, &zero, sizeof zero) != STATUS_SUCCESS;
	if (i != STATUS_SUCCESS) {
	    log_err("Failed to append final zero: %s", status_to_str(i));
	    goto free_buffer_err;
	}
    }

    return 0;

free_req_err:
    httpreq_free(cmd);
free_buffer_err:
    buffer_reset(buffer);
err:
    return -1;
}

static int do_http_post(thttpreq_ctx * http, const char *url, const char *post_data, tbuffer * buffer, const int is_string)
{
    thttpreq *cmd;
    int i;
    int ret_code;
    unsigned char zero = 0;

    buffer_reset(buffer);

    cmd = httpreq_create();
    if (cmd == NULL) {
	log_err("Can't create http request");
	goto err;
    }

    i = httpreq_set_url(cmd, (char *) url);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP req url: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_set_method(cmd, HTTPREQ_METHOD_POST);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP get method: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_set_write_mem_func(cmd, write_to_mem, buffer);
    if (i != STATUS_SUCCESS) {
	log_err("Can't set HTTP callback: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_add_form(cmd, "data", (char *) post_data);
    if (i != STATUS_SUCCESS) {
	log_err("Can't add POST data: %s", status_to_str(i));
	goto free_req_err;
    }

    if (debug)
	log_debug("HTTP POST <%s> <%s>", url, post_data);

    i = httpreq_perform(cmd);
    if (i != STATUS_SUCCESS) {
	log_err("Can't HTTP execute command: %s", status_to_str(i));
	goto free_req_err;
    }

    i = httpreq_get_status(cmd, &ret_code, NULL);
    if (i != STATUS_SUCCESS) {
	log_err("Can't get HTTP status: %s", status_to_str(i));
	goto free_req_err;
    }

    httpreq_free(cmd);

    if (is_string) {
	i = buffer_append(buffer, &zero, sizeof zero) != STATUS_SUCCESS;
	if (i != STATUS_SUCCESS) {
	    log_err("Failed to append final zero: %s", status_to_str(i));
	    goto free_buffer_err;
	}
    }

    if (ret_code != 200) {
	log_err("POST <%s> Failed with errcode <%d> :\n\npost_data=<%s>\nres=<%s>", url, ret_code, post_data, buffer->buf);
	goto free_buffer_err;
    }

    return 0;

free_req_err:
    httpreq_free(cmd);
free_buffer_err:
    buffer_reset(buffer);
err:
    return -1;

}

int sb_list(thttpreq_ctx * http, const char *url, const char *header, char **list, const int list_max)
{
    char req[1024];
    size_t used;
    int i;
    tbuffer buffer;
    char *ptr;
    char *elem;

    memset(&buffer, 0, sizeof buffer);

    used = sb_make_cmd(req, sizeof req, "list", url);
    if (used == 0) {
	log_crit("Can't append command");
	goto err;
    }

    /* Using snprintf will let us to check if 'req' is long enough */
    i = snprintf(req + used, sizeof req - used, "%s", header);
    if (i < 0 || (size_t) i >= sizeof req - used) {
	log_crit("Can't append header");
	goto err;
    }
    used += (size_t) i;

    if (do_http_get(http, req, &buffer, true) < 0)
	goto err;

    i = 0;
    elem = strtok_r((char *) buffer.buf, "\n", &ptr);
    while (elem != NULL) {
	if (elem[0] == 0)
	    continue;

	if (i >= list_max) {
	    log_crit("Failed to add element");
	    goto free_list_err;
	}

	list[i] = strdup(elem);
	if (list[i] == NULL) {
	    log_crit("Failed to allocate element: %s", strerror(errno));
	    goto free_list_err;
	}

	elem = strtok_r(NULL, "\n", &ptr);
	i++;
    }

    free(buffer.buf);

    if (i == 0) {
	fprintf(stderr, "No entries found");
	return -1;
    }

    return i;

free_list_err:
    for (i = 0; i < list_max && list[i] != NULL; i++) {
	free(list[i]);
	list[i] = NULL;
    }
    if (buffer.buf != NULL)
	free(buffer.buf);
err:
    return 0;
}

/*
 * SUB-DATA    = (HOSTKEY COUNT (ADDCHUNKNUM | (ADDCHUNKNUM PREFIX)+))+
 * HOSTKEY     = <4 unsigned bytes>                            # 32-bit hash prefix
 * COUNT       = <1 unsigned byte>
 * ADDCHUNKNUM = <4 byte unsigned integer in network byte order>
 * PREFIX      = <HASHLEN unsigned bytes>

 * In the case of COUNT == 0, only an ADDCHUNKNUM will be present following the COUNT, to indicate the add chunk that contained the host key.
 * In the case of COUNT >= 1, there will be 1 or more [ADDCHUNKNUM PREFIX] pairs.
 */
static ssize_t do_parse_shavar_sub_chunk(struct sbdb_chunk *chunk, const char *sub_data)
{
    const char *ptr = sub_data;
    uint32_t host_key;
    uint8_t add_chunk_count;
    ssize_t off;

#define unpack(ptr, dest) do {                          \
        memcpy((dest), (ptr), sizeof (dest)[0]);        \
        (ptr) += sizeof (dest)[0];                      \
    } while (0)

    unpack(ptr, &host_key);
    unpack(ptr, &add_chunk_count);
#undef unpack

    off = sbdb_chunk_save_sub(chunk, host_key, add_chunk_count, ptr);
    if (off < 0)
	return -1;

    return (ssize_t) ((ptr + off) - sub_data);
}

/*
 * ADD-DATA = (HOSTKEY COUNT [PREFIX]*)+
 * HOSTKEY  = <4 unsigned bytes>                            # 32-bit hash prefix
 * COUNT    = <1 unsigned byte>
 * PREFIX   = <HASHLEN unsigned bytes>
 */
static ssize_t do_parse_shavar_add_chunk(struct sbdb_chunk *chunk, const char *add_data)
{
    const char *ptr = add_data;
    uint32_t host_key;
    uint8_t prefix_count;
    ssize_t off;

#define unpack(ptr, dest) do {                          \
        memcpy((dest), (ptr), sizeof (dest)[0]);        \
        (ptr) += sizeof (dest)[0];                      \
    } while (0)
    unpack(ptr, &host_key);
    unpack(ptr, &prefix_count);
#undef unpack

    off = sbdb_chunk_save_add(chunk, host_key, prefix_count, ptr);
    if (off < 0)
	return -1;

    return (ssize_t) ((ptr + off) - add_data);
}


/*
 * BODY      = (ADD-HEAD | SUB-HEAD)+
 * ADD-HEAD  = "a:" CHUNKNUM ":" HASHLEN ":" CHUNKLEN LF CHUNKDATA   # Length in bytes in decimal
 * SUB-HEAD  = "s:" CHUNKNUM ":" HASHLEN ":" CHUNKLEN LF CHUNKDATA   # Length in bytes in decimal
 * CHUNKNUM  = DIGIT+                                   # Sequence number of the chunk
 * HASHLEN   = DIGIT+                                   # Decimal length of each hash prefix in bytes
 * CHUNKLEN  = DIGIT+                                   # Size of the chunk data in bytes >= 0
 * CHUNKDATA = <CHUNKLEN number of unsigned bytes>
 */
static int parse_redirect_body(struct sbdb_list *list, const char *body, const size_t body_size)
{
    uint32_t chunk_num;
    uint32_t hash_len;
    size_t chunk_len;
    const char *from = body;
    const char *to = body + body_size;
    char *ptr;
    int type;
    size_t off;

    while (from < to) {
	struct sbdb_chunk *chunk;

	if (strncmp(from, "a:", 2) == 0) {
	    from = from + 2;
	    type = sb_add;
	} else if (strncmp(from, "s:", 2) == 0) {
	    from = from + 2;
	    type = sb_sub;
	} else {
	    log_warn("Unexpected head: <%s>", from);
	    goto err;
	}

	chunk_num = (uint32_t) strtoul(from, &ptr, 0);
	if (*ptr != ':') {
	    log_warn("Failed to parse CHUNKNUM");
	    goto err;
	}
	from = ptr + 1;

	hash_len = (uint32_t) strtoul(from, &ptr, 0);
	if (*ptr != ':') {
	    log_warn("Failed to parse HASHLEN");
	    goto err;
	}
	from = ptr + 1;

	chunk_len = strtoul(from, &ptr, 0);
	if (*ptr != '\n') {
	    log_warn("Failed to parse CHUNKLEN");
	    goto err;
	}
	from = ptr + 1;


	if (sbdb_chunk_is_ignored(list, type, chunk_num)) {

	    if (debug > 1)
		log_debug("%s: %s: chunk <%d> ignored", list->name, type == sb_add ? "ADD" : "SUB", chunk_num);

	    off = chunk_len;

	} else {

	    if (debug > 1)
		log_debug("%s: %s: chunk <%d>", list->name, type == sb_add ? "ADD" : "SUB", chunk_num);

	    chunk = sbdb_chunk_new(list, chunk_num, hash_len, type);
	    if (chunk == NULL)
		goto err;

	    off = 0;
	    while (off < chunk_len) {
		ssize_t done;

		if (type == sb_sub) {
		    done = do_parse_shavar_sub_chunk(chunk, from + off);
		    if (done < 0)
			goto err;

		} else {
		    done = do_parse_shavar_add_chunk(chunk, from + off);
		    if (done < 0)
			goto err;
		}

		off += (size_t) done;
	    }
	}

	from += off;
    }

    return 0;

err:
    return -1;
}

static int do_downloads_redirect(int fd, struct sbdb_list *list, const char *url, const time_t now, char **dump_name)
{
    tbuffer buffer;

    memset(&buffer, 0, sizeof buffer);

    if (do_http_get(list->http, url, &buffer, false) < 0)
	goto err;

    if (buffer.buf == NULL || !buffer.buf_size) {
	log_warn("redirect <%s>: No data received", url);
	goto free_buff_err;
    }

    if (parse_redirect_body(list, (char *) buffer.buf, buffer.buf_size) < 0)
	goto free_buff_err;

    if (fd < 0) {

	if (dump_name != NULL && *dump_name != NULL) {
	    log_crit("Internal error");
	    return -1;
	}

	fd = sbcache_dump_open(list->name, now, dump_name);
	if (fd < 0)
	    goto free_buff_err;
    }

    /* TODO: what do I do when I cant save the buffer ? */
    if (sbcache_dump_save(fd, &buffer) < 0)
	goto close_err;

    buffer_reset(&buffer);
    return fd;

close_err:
    close(fd);
    if (dump_name != NULL)
	free(*dump_name);
free_buff_err:
    buffer_reset(&buffer);
err:
    return -1;
}

static int do_process_del(struct sbdb_list *list, const char *adddel, const int type)
{
    const char *ptr = adddel;

    while (*ptr != '\n' && *ptr != 0) {
	char *end;
	uint32_t from;
	uint32_t to;

	from = (uint32_t) strtoul(ptr, &end, 0);
	if (*end == '-') {
	    ptr = end;
	    to = (uint32_t) strtoul(ptr + 1, &end, 0);
	    if (*end != '\n' && *end != 0)
		end++;
	} else if (*end == ',') {
	    to = from;
	    end++;
	} else {
	    log_warn("%s: Failed to parse <%s> %s", list->name, adddel, type == sb_add ? "adddel" : "subdel");
	    return -1;
	}

	if (sbdb_chunk_ignore_add(list, type, from, to) < 0)
	    return -1;

	ptr = end;
    }

    return 0;
}

/*
 * DOWNLOAD response:
 *
 * BODY      = [(REKEY | MAC) LF] NEXT LF (RESET | (LIST LF)+) EOF
 * NEXT      = "n:" DIGIT+                               # Minimum delay before polling again in seconds
 * REKEY     = "e:pleaserekey"
 * RESET     = "r:pleasereset"
 * LIST      = "i:" LISTNAME [MAC] (LF LISTDATA)+
 * LISTNAME  = (LOALPHA | DIGIT | "-")+                  # e.g. "googpub-phish-shavar"
 * MAC       =  (LOALPHA | DIGIT)+
 * LISTDATA  = ((REDIRECT_URL | ADDDEL-HEAD | SUBDEL-HEAD) LF)+
 * REDIRECT_URL = "u:" URL ["," MAC]
 * URL       = Defined in RFC 1738
 * ADDDEL-HEAD  = "ad:" CHUNKLIST
 * SUBDEL-HEAD  = "sd:" CHUNKLIST
 * CHUNKLIST = (RANGE | NUMBER) ["," CHUNKLIST]
 * NUMBER    = DIGIT+                                    # Chunk number >= 1
 * RANGE     = NUMBER "-" NUMBER
 */
int sb_downloads(struct sbdb_list *list, const time_t now, const int host_update, char **dump_name)
{
    tbuffer buffer;
    char req[1024];
    size_t used;
    int i;
    char post_data[1024];
    char *elem;
    char *ptr;
    int nb_redirect;
    int fd;

    memset(&buffer, 0, sizeof buffer);

    log_debug("Updating <%s>", list->name);

    used = sb_make_cmd(req, sizeof req, "downloads", list->url);
    if (used == 0) {
	log_crit("Can't append command");
	goto err;
    }

    /* Using snprintf will let us to check if 'req' is long enough */
    i = snprintf(req + used, sizeof req - used, "%s", list->header);
    if (i < 0 || (size_t) i >= sizeof req - used) {
	log_crit("Can't append header");
	goto err;
    }
    used += (size_t) i;

    if (sbdb_chunk_get(list, post_data, sizeof post_data) < 0)
	goto err;

    if (do_http_post(list->http, req, post_data, &buffer, true) < 0)
	goto err;

    if (dump_name != NULL)
	*dump_name = NULL;
    fd = -1;
    nb_redirect = 0;
    elem = strtok_r((char *) buffer.buf, "\n", &ptr);
    while (elem != NULL) {
	char *redirect;

	if (elem[0] == 0)
	    goto next;

	if (strncmp(elem, "ad:", 3) == 0) {
	    if (do_process_del(list, elem + 3, sb_add) < 0)
		goto err;
	    goto next;
	}

	if (strncmp(elem, "sd:", 3) == 0) {
	    if (do_process_del(list, elem + 3, sb_sub) < 0)
		goto err;
	    goto next;
	}

	if (elem[1] != ':') {
	    log_warn("Unexpected elem <%s>", elem);
	    goto next;
	}

	switch (elem[0]) {
	default:
	    log_warn("Unknown type <%s>", elem);
	    break;

	case 'n':
	    if (sbdb_list_set_next_update(list, now + strtol(elem + 2, NULL, 0)) < 0) {
		log_err("Failed to set next update");
		goto free_buffer_err;
	    }
	    break;

	case 'i':
	    if (strcmp(elem + 2, list->name) != 0) {
		log_err("<%s> asked, got <%s>", list->name, elem + 2);
		goto free_buffer_err;
	    }
	    break;

	case 'u':
	    redirect = elem + 2;
	    fd = do_downloads_redirect(fd, list, redirect, now, dump_name);
	    if (fd < 0) {
		log_err("Failed to follow redirect <%s>", redirect);
		goto free_buffer_err;
	    }
	    nb_redirect++;
	}

next:
	elem = strtok_r(NULL, "\n", &ptr);
    }

    if (fd >= 0)
	close(fd);
    buffer_reset(&buffer);
    if (nb_redirect != 0) {
	log_debug("<%s> is updated, but more to come ; forcing next update to now", list->name);
	sbdb_list_set_next_update(list, now);
    } else {
	log_info("<%s> is uptodate, applying ...", list->name);
	sbdb_chunk_apply(list, host_update);
	log_info("<%s> is ready", list->name);
    }

    return nb_redirect;

free_buffer_err:
    buffer_reset(&buffer);
err:
    log_warn("Failed to update <%s>", list->name);
    return -1;
}

static uint32_t get_key(const char *hostname, const size_t len)
{
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    uint32_t *res = (uint32_t *) sha256;
    SHA256((unsigned char *) hostname, len, sha256);
    return *res;
}

static int do_lookup(struct sbdb_host *host, const char *path)
{
    return sbdb_prefix_lookup(host, path);
}

/*
 * - Remove all leading and trailing dots.
 * - Replace consecutive dots with a single dot.
 * - If the hostname can be parsed as an IP address, it should be normalized to 4 dot-separated decimal values.
 *   The client should handle any legal IP- address encoding, including octal, hex, and fewer than 4 components.
 * - Lowercase the whole string.
 */
static ssize_t canonicalize_hostname(const char *from, const size_t from_len, char *res, const size_t res_size)
{
    const char *ptr;
    const char *to = from + from_len;
    size_t i;

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

    return (ssize_t) i;
}

/*
 * - The sequences "/../" and "/./" in the path should be resolved, by replacing "/./" with "/", and removing "/../" along with the preceding path component.
 * - Runs of consecutive slashes should be replaced with a single slash character.
 */
static inline int hexcar2int(const char c)
{
    if (c >= '0' && c <= '9')
	return c - '0';

    if (c >= 'a' && c <= 'f')
	return 0xa + (c - 'a');

    if (c >= 'A' && c <= 'F')
	return 0xa + (c - 'A');

    /* Note: c is ALWAYS a valid hex character */
    return -1;
}

static int canonicalize_path(const char *from, char *res, const size_t res_size)
{
    const char *ptr;
    size_t used;
    size_t previous_used;
#define path_end(ptr) (*(ptr) == 0 || *(ptr) == '?')

    previous_used = 0;
    used = 0;
    ptr = from;
    while (!path_end(ptr)) {
	const char *start;
	const char *end;
	size_t len;
	size_t i;

	while (*ptr == '/')
	    ptr++;
	if (path_end(ptr))
	    break;
	start = ptr;

	while (*ptr != '/' && !path_end(ptr))
	    ptr++;
	if (ptr == start)
	    break;
	end = ptr;
	len = (size_t) (end - start);

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

	/*
	 * unescape only valid caracters ...
	 */
	for (i = 0; i < len; i++) {
	    if (start[i] == '%' && (i + 2 <= len) && isxdigit(start[i + 1]) && isxdigit(start[i + 2])) {
		const int c = (hexcar2int(start[i + 1]) << 4) | hexcar2int(start[i + 2]);
		if (isascii(c)) {
		    res[used++] = (char) (c & 0xFF);
		    i += 2;
		} else
		    res[used++] = '%';
	    } else
		res[used++] = start[i];
	}

	if (!path_end(end)) {
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
int sb_lookup(struct sbdb_list *list, const char *orig)
{
    const char *ptr;
    const char *url;
    char *host;
    char *path;
    char *host_ptr;
    const size_t buff_len = strlen(orig) + 2;
    char *buff;
    size_t len;
    int found;

    buff = calloc(1, buff_len);
    if (buff == NULL) {
	log_crit("Failed to allocate buffer: %s", strerror(errno));
	goto err;
    }

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
	len = (size_t) (ptr - url);
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
	const size_t l = strlen(ptr);

	path = calloc(1, l + 2);	/* one more to save the last '/' if any ... */
	if (path == NULL)
	    goto free_host_err;

	if (canonicalize_path(ptr, path, l + 2) < 0)
	    goto free_path_err;
    }

    if (sbdb_read_lock(list) < 0)
	goto free_path_err;

    /* At this point, host and path are correct */
    found = false;
    host_ptr = host;
    while (*host_ptr != 0) {
	struct sbdb_host *h;
	const uint32_t host_key = get_key(buff, (size_t) snprintf(buff, buff_len, "%s/", host_ptr));

	h = sbdb_host_get(list, host_key);
	if (h == NULL) {
	    if (debug > 1)
		log_debug("%s: [H_%08x] %s is not found", list->name, host_key, buff);
	    goto next_host;
	}

	if (debug)
	    log_debug("%s: %s is found", list->name, buff);

	/*
	 * Always try to lookup for the url as it is asked on this host
	 */
	found = do_lookup(h, url);
	if (found < 0)
	    goto unlock_err;
	if (found == true)
	    goto done;

	if (path != NULL) {
	    char *path_copy = strdup(path);
	    char *path_end = NULL;

	    for (;;) {

		snprintf(buff, buff_len, "%s/%s%s", host_ptr, path_copy, path_end != NULL ? "/" : "");
		found = do_lookup(h, buff);
		if (found != false) {
		    free(path_copy);
		    if (found < 0)
			goto unlock_err;
		    if (found == true)
			goto done;
		}

		path_end = strrchr(path_copy, '/');
		if (path_end == NULL)
		    break;

		*path_end = 0;
	    }

	    free(path_copy);
	}

	snprintf(buff, buff_len, "%s/", host_ptr);
	found = do_lookup(h, buff);
	if (found < 0)
	    goto unlock_err;
	if (found == true)
	    goto done;

next_host:
	host_ptr = strchr(host_ptr, '.');
	if (host_ptr == NULL || strchr(host_ptr + 1, '.') == NULL)
	    break;
	host_ptr++;
    }

done:
    if (sbdb_read_unlock(list) < 0)
	goto free_path_err;
    if (path != NULL)
	free(path);
    free(host);
    free(buff);
    return found;

unlock_err:
    sbdb_read_unlock(list);
free_path_err:
    if (path != NULL)
	free(path);
free_host_err:
    free(host);
free_buff_err:
    free(buff);
err:
    return -1;
}

void sb_set_debug(const int new_debug)
{
    if (new_debug != debug) {
	log_debug("Setting debug from <%d> to <%d>", debug, new_debug);
	debug = new_debug;
    }

    sbdb_set_debug(new_debug);
}

struct sbdb_list *sb_init(const char *name, const char *key, const char *client_ver, const char *api_ver, const char *url)
{
    char header[128];
    struct sbdb_list *list;
    char path[256];
    time_t when;
    time_t timestamp;
    tbuffer buffer;
    int fd;

    if (!make_header(header, sizeof header, SB_DEFAULT_CLIENT, key, client_ver, (api_ver != NULL) ? api_ver : SB_DEFAULT_PVER))
	goto err;

    list = sbdb_list_new(name, header, (url != NULL) ? url : SB_DEFAULT_URL);
    if (list == NULL)
	goto err;

    memset(&buffer, 0, sizeof buffer);

    log_debug("Initializing <%s>", list->name);

    timestamp = 0;
    while (sbcache_dump_find_younger(list->name, timestamp, path, sizeof path, &when) == true) {

	fd = open(path, O_RDONLY);
	if (fd < 0) {
	    log_warn("Failed to open <%s> : %s", path, strerror(errno));
	    goto free_err;
	}

	log_debug("Loading <%s> from cache <%s>", list->name, path);
	for (;;) {
	    int i;

	    i = sbcache_dump_load_next(fd, &buffer);
	    if (i < 0)
		goto close_err;
	    if (i == 0)
		break;

	    if (parse_redirect_body(list, (char *) buffer.buf, buffer.buf_size) < 0)
		goto close_err;
	}

	close(fd);
	timestamp = when;
    }

    return list;

close_err:
    close(fd);
free_err:
    buffer_reset(&buffer);
    sbdb_list_free(list);
err:
    return NULL;
}

tbuffer *sb_dump_to_buffer(const char *dumpfile)
{
    tbuffer *buffer;

    buffer = buffer_create();
    if (buffer == NULL) {
	log_crit("Failed to create buffer : %s", strerror(errno));
	goto err;
    }

    if (sbcache_dump_to_buffer(dumpfile, buffer) < 0)
	goto free_buff_err;

    return buffer;

free_buff_err:
    buffer_free(buffer);
err:
    return NULL;
}

int sb_buffer_to_dump(struct sbdb_list *list, const time_t timestamp, tbuffer * buffer, const int host_update)
{
    size_t off;

    off = 0;
    while (off < buffer->buf_size) {
	__typeof__(buffer->buf_size) s;
	const char *data;

	memcpy(&s, buffer->buf + off, sizeof s);
	off += sizeof s;

	data = (char *) (buffer->buf + off);
	off += s;

	if (host_update) {
	    if (parse_redirect_body(list, data, s) < 0)
		goto err;
	}
    }

    if (off != buffer->buf_size) {
	log_warn("%s: buffer was not completly parsed !", list->name);
	goto err;
    }

    if (sbcache_buffer_to_dump(list->name, timestamp, buffer) < 0)
	goto err;

    buffer_reset(buffer);
    return 0;

err:
    return -1;
}

int sb_set_url(struct sbdb_list *list, const char *url)
{
    if (url == NULL)
	url = SB_DEFAULT_URL;

    if (sbdb_set_url(list, (url != NULL) ? url : SB_DEFAULT_URL) < 0)
	return -1;

    if (debug)
	log_debug("%s: API URL set to <%s>", list->name, url);
    return 0;
}

int sb_set_param(struct sbdb_list *list, const char *key, const char *client_ver, const char *api_ver)
{
    char header[128];

    if (!make_header(header, sizeof header, SB_DEFAULT_CLIENT, key, client_ver, (api_ver != NULL) ? api_ver : SB_DEFAULT_PVER))
	return -1;

    if (sbdb_set_header(list, header) < 0)
	return -1;

    if (debug)
	log_debug("%s: API key set to <%s>", list->name, key);
    return 0;
}
