
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sbdb.c 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#define PFX "[SBDB] "
#include "logger.h"
#include "util.h"
#include "rwlock.h"
#include "httpreq.h"
#include "sbdb.h"

#define HOST_HASH(host) ((host) % SBDB_HOST_LIST_MAX_HASH)
#define CHUNK_HASH(chunk_num) ((chunk_num) % SBDB_CHUNK_LIST_MAX_HASH)

static int debug = 0;
void sbdb_set_debug(const int new_debug)
{
    if (new_debug != debug) {
	log_debug("Setting debug from <%d> to <%d>", debug, new_debug);
	debug = new_debug;
    }
}

static struct sbdb_chunk_add *new_chunk_add(struct sbdb_chunk *chunk, const uint32_t host_key)
{
    struct sbdb_chunk_add *add;

    add = calloc(1, sizeof add[0]);
    if (add == NULL) {
	log_crit("Cant allocate a new chunk_add: %s", strerror(errno));
	goto err;
    }

    add->host_key = host_key;
    add->chunk_add_next = NULL;
    add->chunk_add_prev = chunk->chunk_add_last;

    if (chunk->chunk_add_last != NULL)
	chunk->chunk_add_last->chunk_add_next = add;
    else
	chunk->chunk_add_first = add;
    chunk->chunk_add_last = add;
    return add;

err:
    return NULL;
}

static void free_chunk_add(struct sbdb_chunk *chunk, struct sbdb_chunk_add *add)
{
    if (add->chunk_add_next != NULL)
	add->chunk_add_next->chunk_add_prev = add->chunk_add_prev;
    else
	chunk->chunk_add_last = add->chunk_add_prev;

    if (add->chunk_add_prev != NULL)
	add->chunk_add_prev->chunk_add_next = add->chunk_add_next;
    else
	chunk->chunk_add_first = add->chunk_add_next;

    if (add->prefix != NULL)
	free(add->prefix);
    free(add);
}

static struct sbdb_chunk_add *get_chunk_add(const struct sbdb_chunk *chunk, const uint32_t host_key)
{
    struct sbdb_chunk_add *add;

    for (add = chunk->chunk_add_first; add != NULL; add = add->chunk_add_next) {
	if (add->host_key == host_key)
	    break;
    }

    return add;
}

static struct sbdb_chunk_sub *new_chunk_sub(struct sbdb_chunk *chunk, const uint32_t host_key)
{
    struct sbdb_chunk_sub *sub;

    sub = calloc(1, sizeof sub[0]);
    if (sub == NULL) {
	log_crit("Cant allocate a new chunk_sub: %s", strerror(errno));
	goto err;
    }

    sub->host_key = host_key;
    sub->chunk_sub_next = NULL;
    sub->chunk_sub_prev = chunk->chunk_sub_last;

    if (chunk->chunk_sub_last != NULL)
	chunk->chunk_sub_last->chunk_sub_next = sub;
    else
	chunk->chunk_sub_first = sub;
    chunk->chunk_sub_last = sub;
    return sub;

err:
    return NULL;
}

static void free_chunk_sub(struct sbdb_chunk *chunk, struct sbdb_chunk_sub *sub)
{
    if (sub->chunk_sub_next != NULL)
	sub->chunk_sub_next->chunk_sub_prev = sub->chunk_sub_prev;
    else
	chunk->chunk_sub_last = sub->chunk_sub_prev;

    if (sub->chunk_sub_prev != NULL)
	sub->chunk_sub_prev->chunk_sub_next = sub->chunk_sub_next;
    else
	chunk->chunk_sub_first = sub->chunk_sub_next;

    if (sub->add_chunk_count > 0 && sub->entry.table != NULL)
	free(sub->entry.table);

    free(sub);
}

static inline struct sbdb_chunk *get_chunk(const struct sbdb_list *list, const uint32_t chunk_num)
{
    struct sbdb_chunk *chunk;
    const uint32_t chunk_hash = CHUNK_HASH(chunk_num);

    for (chunk = list->chunk_table[chunk_hash].first; chunk != NULL; chunk = chunk->chunk_hash_next) {
	if (chunk->chunk_num == chunk_num)
	    break;
    }

    return chunk;
}

static struct sbdb_chunk *new_chunk(struct sbdb_list *list, const uint32_t chunk_num, const uint32_t hash_len)
{
    struct sbdb_chunk *chunk;
    const uint32_t chunk_hash = CHUNK_HASH(chunk_num);

    chunk = calloc(1, sizeof chunk[0]);
    if (chunk == NULL) {
	log_crit("Cant allocate a new chunk: %s", strerror(errno));
	goto err;
    }

    chunk->chunk_num = chunk_num;
    chunk->hash_len = hash_len;

    /*
     * A linear list
     * TODO: have to be sorted
     */
    chunk->chunk_list_next = NULL;
    chunk->chunk_list_prev = list->chunk_list.last;
    if (list->chunk_list.last != NULL)
	list->chunk_list.last->chunk_list_next = chunk;
    else
	list->chunk_list.first = chunk;
    list->chunk_list.last = chunk;

    /*
     * A list for hash table
     */
    chunk->chunk_hash_next = NULL;
    chunk->chunk_hash_prev = list->chunk_table[chunk_hash].last;
    if (list->chunk_table[chunk_hash].last != NULL)
	list->chunk_table[chunk_hash].last->chunk_hash_next = chunk;
    else
	list->chunk_table[chunk_hash].first = chunk;
    list->chunk_table[chunk_hash].last = chunk;

    return chunk;

err:
    return NULL;
}

static void free_chunk(struct sbdb_list *list, struct sbdb_chunk *chunk)
{
    const uint32_t chunk_hash = CHUNK_HASH(chunk->chunk_num);

    /*
     * Unlink from list
     */
    if (chunk->chunk_list_prev != NULL)
	chunk->chunk_list_prev->chunk_list_next = chunk->chunk_list_next;
    else
	list->chunk_list.first = chunk->chunk_list_next;

    if (chunk->chunk_list_next != NULL)
	chunk->chunk_list_next->chunk_list_prev = chunk->chunk_list_prev;
    else
	list->chunk_list.last = chunk->chunk_list_prev;

    /*
     * Unlink from hash
     */
    if (chunk->chunk_hash_prev != NULL)
	chunk->chunk_hash_prev->chunk_hash_next = chunk->chunk_hash_next;
    else
	list->chunk_table[chunk_hash].first = chunk->chunk_hash_next;

    if (chunk->chunk_hash_next != NULL)
	chunk->chunk_hash_next->chunk_hash_prev = chunk->chunk_hash_prev;
    else
	list->chunk_table[chunk_hash].last = chunk->chunk_hash_prev;

    /*
     * Remove pending add
     */
    while (chunk->chunk_add_first != NULL)
	free_chunk_add(chunk, chunk->chunk_add_first);

    /*
     * Remove pending sub
     */
    while (chunk->chunk_sub_first != NULL)
	free_chunk_sub(chunk, chunk->chunk_sub_first);

    free(chunk);
}

static inline struct sbdb_prefix *get_prefix(struct sbdb_host *host, const uint8_t * prefix, const size_t prefix_len)
{
    struct sbdb_prefix *ptr;

    for (ptr = host->prefix_first; ptr != NULL; ptr = ptr->prefix_next) {

	if (ptr->prefix_len == prefix_len && memcmp(&ptr->prefix_key, prefix, prefix_len) == 0)
	    return ptr;
    }

    return NULL;
}

static inline struct sbdb_prefix *new_prefix(struct sbdb_host *host, const uint8_t * prefix, const size_t prefix_len)
{
    struct sbdb_prefix *host_prefix;

    host_prefix = calloc(1, sizeof host_prefix[0] - sizeof host_prefix[0].prefix_key + prefix_len);
    if (host_prefix == NULL) {
	log_crit("Cant allocate a new prefix: %s", strerror(errno));
	return NULL;
    }

    memcpy(&host_prefix->prefix_key, prefix, prefix_len);
    host_prefix->prefix_len = prefix_len;
    host_prefix->prefix_next = NULL;
    host_prefix->prefix_prev = host->prefix_last;

    if (host->prefix_last != NULL)
	host->prefix_last->prefix_next = host_prefix;
    else
	host->prefix_first = host_prefix;
    host->prefix_last = host_prefix;

    return host_prefix;
}

static inline void remove_prefix(struct sbdb_host *host, struct sbdb_prefix *prefix)
{

    if (prefix->prefix_next != NULL)
	prefix->prefix_next->prefix_prev = prefix->prefix_prev;
    else
	host->prefix_last = prefix->prefix_prev;

    if (prefix->prefix_prev != NULL)
	prefix->prefix_prev->prefix_next = prefix->prefix_next;
    else
	host->prefix_first = prefix->prefix_next;

    free(prefix);
}

static inline struct sbdb_host *get_host(const struct sbdb_list *list, const uint32_t host_key, const uint32_t host_hash)
{
    struct sbdb_host *ptr;

    for (ptr = list->host_table[host_hash].host_first; ptr != NULL; ptr = ptr->host_next) {
	if (ptr->host_key == host_key)
	    return ptr;
    }

    return NULL;
}

static inline struct sbdb_host *new_host(struct sbdb_list *list, const uint32_t host_key, const uint32_t host_hash)
{
    struct sbdb_host *host;

    host = calloc(1, sizeof host[0]);
    if (host == NULL) {
	log_crit("Cant allocate a new host: %s", strerror(errno));
	return NULL;
    }

    host->host_key = host_key;
    host->host_next = NULL;
    host->host_prev = list->host_table[host_hash].host_last;

    if (list->host_table[host_hash].host_last != NULL)
	list->host_table[host_hash].host_last->host_next = host;
    else
	list->host_table[host_hash].host_first = host;
    list->host_table[host_hash].host_last = host;

    return host;
}

static void free_host(struct sbdb_list *list, struct sbdb_host *host, const uint32_t host_hash)
{
    if (host->host_prev != NULL)
	host->host_prev->host_next = host->host_next;
    else
	list->host_table[host_hash].host_first = host->host_next;

    if (host->host_next != NULL)
	host->host_next->host_prev = host->host_prev;
    else
	list->host_table[host_hash].host_last = host->host_prev;

    while (host->prefix_first != NULL)
	remove_prefix(host, host->prefix_first);

    free(host);
}

struct sbdb_list *sbdb_list_new(const char *name, const char *header, const char *url)
{
    struct sbdb_list *list;

    list = calloc(1, sizeof list[0]);
    if (list == NULL) {
	log_crit("Failed to allocate list <%s>: %s", name, strerror(errno));
	goto err;
    }

    list->name = strdup(name);
    if (list->name == NULL) {
	log_crit("Failed to allocate list name : %s", strerror(errno));
	goto free_err;
    }

    list->header = strdup(header);
    if (list->header == NULL) {
	log_crit("Failed to allocate header : %s", strerror(errno));
	goto free_name_err;
    }

    list->url = strdup(url);
    if (list->header == NULL) {
	log_crit("Failed to allocate url : %s", strerror(errno));
	goto free_header_err;
    }

    list->http = httpreq_ctx_create();
    if (list->http == NULL) {
	log_err("Can't create httpreq context");
	goto free_url_err;
    }

    if (rwlock_init(&list->lock) < 0)
	goto free_http_err;

    return list;

free_http_err:
    httpreq_ctx_free(list->http);
free_url_err:
    free(list->url);
free_header_err:
    free(list->header);
free_name_err:
    free(list->name);
free_err:
    free(list);
err:
    return NULL;
}

struct sbdb_chunk *sbdb_chunk_new(struct sbdb_list *list, const uint32_t chunk_num, const uint32_t hash_len, const int type)
{
    struct sbdb_chunk *chunk;
    struct sbdb_chunk *nouvo;

    nouvo = NULL;
    if (rwlock_write_lock(&list->lock) < 0)
	return NULL;

    chunk = get_chunk(list, chunk_num);
    if (chunk == NULL) {
	nouvo = new_chunk(list, chunk_num, hash_len);
	chunk = nouvo;
    }

    /* not very elegant, but google seems to send some 'empty' chunk ... */
    if (type == sb_add)
	chunk->chunk_add_added++;
    else
	chunk->chunk_sub_added++;


    if (rwlock_write_unlock(&list->lock) < 0) {
	if (nouvo != NULL)
	    free_chunk(list, nouvo);
	chunk = NULL;
    }

    return chunk;
}

static void chunk_sub_debug(const struct sbdb_chunk *chunk)
{
    const struct sbdb_chunk_sub *sub;

    for (sub = chunk->chunk_sub_first; sub != NULL; sub = sub->chunk_sub_next) {

	if (sub->add_chunk_count == 0)
	    log_debug("[C_%08x][S_%p][H_%08x][C_%08x] prefix <*>", chunk->chunk_num, (void *) sub, sub->host_key, sub->entry.add_chunk_num);
	else {
	    int i;

	    for (i = 0; i < sub->add_chunk_count; i++) {
		char prefix[80];

		buffer_to_str(&sub->entry.table[i].prefix, chunk->hash_len, prefix, sizeof prefix);
		log_debug("[C_%08x][S_%p][H_%08x][C_%08x] prefix_%03d/%03d <%s>", chunk->chunk_num, (void *) sub, sub->host_key, sub->entry.table[i].add_chunk_num, i + 1, sub->add_chunk_count, prefix);
	    }
	}
    }
}

static void chunk_add_debug(const struct sbdb_chunk *chunk)
{
    const uint32_t hash_len = chunk->hash_len;
    const struct sbdb_chunk_add *add = chunk->chunk_add_first;

    for (add = chunk->chunk_add_first; add != NULL; add = add->chunk_add_next) {

	if (add->prefix_count == 0)
	    log_debug("[C_%08x][A_%p][H_%08x] prefix <*>", chunk->chunk_num, (void *) add, add->host_key);
	else {
	    int i;

	    for (i = 0; i < add->prefix_count; i++) {
		char prefix[80];
		const int s = (int) SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len);
		buffer_to_str(&add->prefix[i * s], hash_len, prefix, sizeof prefix);
		log_debug("[C_%08x][A_%p][H_%08x] prefix_%03d/%03d <%s>", chunk->chunk_num, (void *) add, add->host_key, i + 1, add->prefix_count, prefix);
	    }
	}
    }
}

void sbdb_chunk_debug(const struct sbdb_list *list)
{
    struct sbdb_chunk *chunk;

    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next) {
	log_debug("+----");
	chunk_add_debug(chunk);
	chunk_sub_debug(chunk);
    }
}

ssize_t sbdb_chunk_save_sub(struct sbdb_chunk *chunk, const uint32_t host_key, const uint8_t add_chunk_count, const char *add_chunk_ptr)
{
    const char *ptr = add_chunk_ptr;
    struct sbdb_chunk_sub *sub;
    const uint32_t hash_len = chunk->hash_len;

    sub = new_chunk_sub(chunk, host_key);
    if (sub == NULL)
	goto err;

    sub->host_key = host_key;
    sub->add_chunk_count = add_chunk_count;

#define unpack(ptr, dest) do {                          \
        memcpy((dest), (ptr), sizeof (dest)[0]);        \
        (ptr) += sizeof (dest)[0];                      \
    } while (0)

    if (sub->add_chunk_count == 0) {
	unpack(ptr, &sub->entry.add_chunk_num);
	sub->entry.add_chunk_num = ntohl(sub->entry.add_chunk_num);

	if (debug > 2)
	    log_debug("[C_%08x][S_%p][H_%08x][C_%08x] prefix <*> added", chunk->chunk_num, (void *) sub, sub->host_key, sub->entry.add_chunk_num);
    } else {
	int i;
	const size_t entry_size = SBDB_CHUNK_SUB_TABLE_SIZE(hash_len);

	sub->entry.table = calloc(sub->add_chunk_count, entry_size);
	if (sub->entry.table == NULL) {
	    log_crit("Failed to create table of <%d> * <%zd>", sub->add_chunk_count, entry_size);
	    goto decrease_err;
	}

	for (i = 0; i < sub->add_chunk_count; i++) {
	    unpack(ptr, &sub->entry.table[i].add_chunk_num);
	    sub->entry.table[i].add_chunk_num = ntohl(sub->entry.table[i].add_chunk_num);
	    memcpy(&sub->entry.table[i].prefix, ptr, hash_len);
	    ptr += hash_len;
	}

	for (i = 0; i < sub->add_chunk_count; i++) {
	    char prefix[80];

	    buffer_to_str(&sub->entry.table[i].prefix, chunk->hash_len, prefix, sizeof prefix);
	    if (debug > 2)
		log_debug("[C_%08x][S_%p][H_%08x][C_%08x] prefix_%03d/%03d <%s> added", chunk->chunk_num, (void *) sub, sub->host_key, sub->entry.table[i].add_chunk_num, i + 1, sub->add_chunk_count, prefix);
	}
    }
#undef unpack

    return (ssize_t) (ptr - add_chunk_ptr);

decrease_err:
    free_chunk_sub(chunk, sub);
err:
    return -1;
}

ssize_t sbdb_chunk_save_add(struct sbdb_chunk * chunk, const uint32_t host_key, const uint8_t prefix_count, const char *prefix_ptr)
{
    const char *ptr = prefix_ptr;
    struct sbdb_chunk_add *add;
    const uint32_t hash_len = chunk->hash_len;

    add = new_chunk_add(chunk, host_key);
    if (add == NULL)
	goto err;

    add->prefix_count = prefix_count;
    if (add->prefix_count != 0) {
	int i;

	add->prefix_wildcard = false;
	add->prefix = calloc(add->prefix_count, SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len));
	if (add->prefix == NULL) {
	    log_crit("Failed to create table of <%d> * <%zd>", add->prefix_count, SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len));
	    goto free_chunk_add_err;
	}

	for (i = 0; i < add->prefix_count; i++) {
	    const size_t s = SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len);

	    memcpy(&add->prefix[i * (int) s], ptr, hash_len);
	    ptr += hash_len;
	}

	for (i = 0; i < add->prefix_count; i++) {
	    char prefix[80];
	    const int s = (int) SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len);
	    buffer_to_str(&add->prefix[i * s], hash_len, prefix, sizeof prefix);
	    if (debug > 2)
		log_debug("[C_%08x][A_%p][H_%08x] prefix_%03d/%03d <%s> added", chunk->chunk_num, (void *) add, add->host_key, i + 1, add->prefix_count, prefix);
	}

    } else {
	add->prefix = NULL;
	add->prefix_wildcard = true;
	if (debug > 2)
	    log_debug("[C_%08x][A_%p][H_%08x] prefix <*> added", chunk->chunk_num, (void *) add, add->host_key);
    }

    return (ssize_t) (ptr - prefix_ptr);

free_chunk_add_err:
    free_chunk_add(chunk, add);
err:
    return -1;
}

/*
 * return true if the substraction have been done
 */
static int chunk_sub_apply(struct sbdb_list *list, const uint32_t chunk_num_, const uint32_t hash_len_, struct sbdb_chunk_sub *sub, const int host_update)
{
    const uint32_t host_key = sub->host_key;
    struct sbdb_chunk *chunk;
    struct sbdb_chunk_add *add;
    int i;

    if (sub->add_chunk_count == 0) {

	chunk = get_chunk(list, sub->entry.add_chunk_num);
	if (chunk == NULL) {
	    if (debug > 2)
		log_debug("[C_%08x][S_%p][H_%08x] Cant find [C_%08x] for now", chunk_num_, (void *) sub, host_key, sub->entry.add_chunk_num);
	    return false;
	}

	add = get_chunk_add(chunk, host_key);
	if (add == NULL) {
	    if (debug > 2)
		log_debug("[C_%08x][S_%p][H_%08x] Cant find [C_%08x][A_xxxxxxxx][H_%08x] for now", chunk_num_, (void *) sub, host_key, sub->entry.add_chunk_num, host_key);
	    return false;
	}

	if (debug > 2)
	    log_debug("[C_%08x][S_%p][H_%08x] applied to [C_%08x][A_%p][H_%08x]", chunk_num_, (void *) sub, host_key, chunk->chunk_num, (void *) add, add->host_key);

	if (host_update)
	    sbdb_host_free(list, add->host_key);
	free_chunk_add(chunk, add);
	return true;
    }

    for (i = 0; i < sub->add_chunk_count; i++) {
	const uint32_t n = sub->entry.table[i].add_chunk_num;
	uint8_t *prefix;
	int j;

	chunk = get_chunk(list, n);
	if (chunk == NULL) {
	    if (debug > 2)
		log_debug("[C_%08x][S_%p][H_%08x] Cant find prefix for [C_%08x] for now", chunk_num_, (void *) sub, host_key, n);
	    return false;
	}

	if (chunk->hash_len != hash_len_) {
	    log_warn("[C_%08x][S_%p][H_%08x] points to [C_%08x], but hash_len differs (<%d> != <%d>)", chunk_num_, (void *) sub, host_key, n, chunk->hash_len, hash_len_);
	    return false;
	}

	add = get_chunk_add(chunk, host_key);
	if (add == NULL) {
	    if (debug > 2)
		log_debug("[C_%08x][S_%p][H_%08x] Cant find prefix [C_%08x][A_xxxxxxxx][H_%08x] for now", chunk_num_, (void *) sub, host_key, n, host_key);
	    return false;
	}

	for (j = 0; j < add->prefix_count; j++) {
	    prefix = &add->prefix[j * (int) SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len_)];
	    if (memcmp(prefix, &sub->entry.table[i].prefix, hash_len_) == 0)
		break;
	}

	if (j == add->prefix_count) {
	    if (debug > 2) {
		char str[80];
		buffer_to_str(&sub->entry.table[i].prefix, hash_len_, str, sizeof str);
		log_debug("[C_%08x][S_%p][H_%08x] Cant find prefix <%s> on [C_%08x][A_%p][H_%08x] for now", chunk_num_, (void *) sub, host_key, str, n, (void *) add, host_key);
	    }
	    return false;
	}

	if (j + 1 < add->prefix_count)
	    memmove(prefix, prefix + hash_len_, hash_len_);
	add->prefix_count--;

	if (debug > 2) {
	    char str[80];
	    buffer_to_str(&sub->entry.table[i].prefix, hash_len_, str, sizeof str);
	    log_debug("[C_%08x][S_%p][H_%08x] prefix <%s> applied on [C_%08x][A_%p][H_%08x] ", chunk_num_, (void *) sub, host_key, str, n, (void *) add, host_key);
	}

	/*
	 * There is no prefix, and it was not a wildcard prefix: we can now remove the add
	 */
	if (add->prefix_count == 0 && !add->prefix_wildcard) {
	    if (debug > 2)
		log_debug("[C_%08x][A_%p][H_%08x] is now empty, removing it", n, (void *) add, host_key);
	    if (host_update)
		sbdb_host_free(list, add->host_key);
	    free_chunk_add(chunk, add);
	}
    }

    return true;
}

int sbdb_chunk_apply(struct sbdb_list *list, const int host_update)
{
    struct sbdb_chunk *chunk;
    int sub_done = 0;
    int sub_asked = 0;

    if (debug)
	log_debug("%s: Removing unusable chunks", list->name);

    /*
     * Apply substractions
     */
    sub_done = 0;
    sub_asked = 0;
    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next) {
	struct sbdb_chunk_sub *sub;

	if (debug > 1)
	    log_debug("[C_%08x] Applying chunk substractions ...", chunk->chunk_num);

	sub = chunk->chunk_sub_first;
	while (sub != NULL) {
	    struct sbdb_chunk_sub *next = sub->chunk_sub_next;

	    sub_asked++;

	    /* TODO: manage errors */
	    if (chunk_sub_apply(list, chunk->chunk_num, chunk->hash_len, sub, host_update) == true)
		sub_done++;

	    free_chunk_sub(chunk, sub);
	    sub = next;
	}
    }

    if (debug)
	log_debug("%s: <%d/%d> substractions done", list->name, sub_done, sub_asked);

    if (debug)
	log_debug("%s: Adding hosts ...", list->name);

    /*
     * Apply additions
     */
    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next) {
	struct sbdb_chunk_add *add;

	if (debug > 1)
	    log_debug("[C_%08x] Applying chunk additions ...", chunk->chunk_num);

	add = chunk->chunk_add_first;
	while (add != NULL) {
	    struct sbdb_chunk_add *next = add->chunk_add_next;

	    if (host_update) {
		struct sbdb_host *host;

		/* TODO: manage errors */
		host = sbdb_host_add(list, add->host_key);
		if (host != NULL) {

		    if (add->prefix_wildcard) {
			while (host->prefix_first)
			    remove_prefix(host, host->prefix_first);
		    } else {
			int i;

			for (i = 0; i < add->prefix_count; i++) {
			    const int s = (int) SBDB_CHUNK_ADD_PREFIX_SIZE(chunk->hash_len);
			    sbdb_prefix_add(host, &add->prefix[i * s], chunk->hash_len);
			}
		    }
		}
	    }

	    free_chunk_add(chunk, add);
	    add = next;
	}
    }

    if (debug > 2)
	sbdb_list_debug(list);
    return 0;
}

struct sbdb_host *sbdb_host_add(struct sbdb_list *list, const uint32_t host_key)
{
    const uint32_t host_hash = HOST_HASH(host_key);
    struct sbdb_host *host;

    host = get_host(list, host_key, host_hash);
    if (host == NULL)
	host = new_host(list, host_key, host_hash);

    return host;
}

void sbdb_host_free(struct sbdb_list *list, const uint32_t host_key)
{
    const uint32_t host_hash = HOST_HASH(host_key);
    struct sbdb_host *host;

    host = get_host(list, host_key, host_hash);
    if (host != NULL)
	free_host(list, host, host_hash);
}

struct sbdb_host *sbdb_host_get(struct sbdb_list *list, const uint32_t host_key)
{
    return get_host(list, host_key, HOST_HASH(host_key));
}

int sbdb_host_lookup(struct sbdb_list *list, const uint32_t host_key)
{
    struct sbdb_host *host;

    if (rwlock_read_lock(&list->lock) < 0)
	return -1;

    host = sbdb_host_get(list, host_key);

    if (rwlock_read_unlock(&list->lock) < 0)
	return -1;

    if (host != NULL)
	return true;
    return false;
}

static void get_hash(const void *data, const size_t data_len, uint8_t * res, const size_t res_len)
{
    uint8_t sha256[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char *) data, data_len, sha256);

    if (res_len <= sizeof sha256)
	memcpy(res, sha256, res_len);
    else {
	memcpy(res, sha256, sizeof sha256);
	memset(res + sizeof sha256, 0, res_len - sizeof sha256);
    }
}

int sbdb_prefix_lookup(const struct sbdb_host *host, const char *path)
{
    uint8_t *hash = NULL;
    size_t size = 0;
    struct sbdb_prefix *prefix;

    if (debug)
	log_debug("Looking for prefix <%s>", path);

    /* If there is no prefix, the host matches */
    if (host->prefix_first == NULL)
	return true;

    for (prefix = host->prefix_first; prefix != NULL; prefix = prefix->prefix_next) {

	/*
	 * Update hash if lenght differs ...
	 */
	if (size != prefix->prefix_len) {

	    if (size < prefix->prefix_len) {
		uint8_t *ptr;

		ptr = realloc(hash, prefix->prefix_len);
		if (ptr == NULL) {
		    log_crit("Failed to allocate path hash : %s", strerror(errno));
		    goto free_err;
		}

		hash = ptr;
		size = prefix->prefix_len;
	    }

	    get_hash(path, strlen(path), hash, size);
	}

	if (memcmp(hash, &prefix->prefix_key, prefix->prefix_len) == 0)
	    break;
    }

    if (hash != NULL)
	free(hash);

    if (prefix == NULL)
	return false;
    return true;

free_err:
    if (hash != NULL)
	free(hash);
    return -1;
}

struct sbdb_prefix *sbdb_prefix_add(struct sbdb_host *host, const uint8_t * prefix, const size_t prefix_len)
{
    struct sbdb_prefix *host_prefix;

    host_prefix = get_prefix(host, prefix, prefix_len);
    if (host_prefix == NULL)
	host_prefix = new_prefix(host, prefix, prefix_len);

    return host_prefix;
}

int sbdb_list_free(struct sbdb_list *list)
{
    uint32_t i;

    if (rwlock_write_lock(&list->lock) < 0)
	return -1;

    while (list->chunk_list.first != NULL)
	free_chunk(list, list->chunk_list.first);

    for (i = 0; i < (uint32_t) (sizeof list->host_table / sizeof list->host_table[0]); i++) {
	while (list->host_table[i].host_first != NULL)
	    free_host(list, list->host_table[i].host_first, i);
    }

    if (list->add_ignore != NULL) {
	free(list->add_ignore);
	list->add_ignore = NULL;
    }

    if (list->sub_ignore != NULL) {
	free(list->sub_ignore);
	list->sub_ignore = NULL;
    }

    if (rwlock_write_unlock(&list->lock) < 0)
	return -1;

    rwlock_free(&list->lock);
    httpreq_ctx_free(list->http);
    free(list->url);
    free(list->header);
    free(list->name);
    free(list);

    return 0;
}

static void prefix_debug(const uint32_t host_key, const struct sbdb_prefix *prefix)
{
    char str[80];

    buffer_to_str(&prefix->prefix_key, prefix->prefix_len, str, sizeof str);
    log_debug("%08x %s", host_key, str);
}

static void host_debug(const struct sbdb_host *host)
{
    struct sbdb_prefix *prefix;

    if (host->prefix_first == NULL)
	log_debug("%08x", host->host_key);
    else {
	for (prefix = host->prefix_first; prefix != NULL; prefix = prefix->prefix_next)
	    prefix_debug(host->host_key, prefix);
    }
}

static void host_list_debug(const struct sbdb_host_list *host_list)
{
    struct sbdb_host *ptr;

    for (ptr = host_list->host_first; ptr != NULL; ptr = ptr->host_next)
	host_debug(ptr);
}

static void chunk_debug(const struct sbdb_chunk *chunk)
{
    log_debug("+  chunk[%08x] SUB", chunk->chunk_num);
}

int sbdb_list_debug(struct sbdb_list *list)
{
    struct sbdb_chunk *chunk;
    uint32_t i;

    if (rwlock_read_lock(&list->lock) < 0)
	return -1;

    log_debug("+-- list[%s]", list->name);

    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next)
	chunk_debug(chunk);

    for (i = 0; i < (uint32_t) (sizeof list->host_table / sizeof list->host_table[0]); i++)
	host_list_debug(&list->host_table[i]);

    return rwlock_read_unlock(&list->lock);
}

int sbdb_list_set_next_update(struct sbdb_list *list, const time_t when)
{
    if (rwlock_write_lock(&list->lock) < 0)
	return -1;

    list->next_update = when;

    return rwlock_write_unlock(&list->lock);
}

time_t sbdb_list_get_next_update(struct sbdb_list * list)
{
    time_t when;

    if (rwlock_read_lock(&list->lock) < 0)
	return -1;

    when = list->next_update;

    if (rwlock_read_unlock(&list->lock) < 0)
	return -1;

    return when;
}

int sbdb_chunk_get(struct sbdb_list *list, char *res, const int res_size)
{
    struct sbdb_chunk *chunk;
    uint32_t last;
    int used;
    int used_save;
#define safe_add(...) do {                                              \
        const int n = snprintf(res + used, (size_t)(res_size - used), __VA_ARGS__); \
        if (n >= res_size - used) {                                     \
            rwlock_read_unlock(&list->lock);                            \
            log_crit("Too small buffer !");                             \
            return -1;                                                  \
        }                                                               \
        used += n;                                                      \
    }                                                                   \
    while (0)

    used = 0;
    safe_add("%s;", list->name);
    used_save = used;
    safe_add("a:");
    last = 0;

    rwlock_read_lock(&list->lock);

    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next) {
	if (chunk->chunk_add_added == 0)
	    continue;

	if (chunk->chunk_num != last + 1) {
	    if (last != 0)
		safe_add("%d,%d-", last, chunk->chunk_num);
	    else
		safe_add("%d-", chunk->chunk_num);
	}

	last = chunk->chunk_num;
    }
    if (last > 0)
	safe_add("%d:", last);
    else {
	res[used_save] = 0;
	used = used_save;
    }

    used_save = used;
    safe_add(":s:");
    last = 0;
    for (chunk = list->chunk_list.first; chunk != NULL; chunk = chunk->chunk_list_next) {
	if (chunk->chunk_sub_added == 0)
	    continue;

	if (chunk->chunk_num != last + 1) {
	    if (last != 0)
		safe_add("%d,%d-", last, chunk->chunk_num);
	    else
		safe_add("%d-", chunk->chunk_num);
	}

	last = chunk->chunk_num;
    }

    if (last > 0)
	safe_add("%d", last);
    else {
	res[used_save] = 0;
	used = used_save;
    }

    safe_add("\n");

#undef safe_add
    rwlock_read_unlock(&list->lock);
    return used;
}

int sbdb_chunk_ignore_add(struct sbdb_list *list, const int type, const uint32_t from, const uint32_t to)
{
    uint32_t chunk_num;

    /*
     * Save the ignore list
     */
    if (type == sb_add) {
	struct sbdb_chunk_ignore *ignore;

	ignore = realloc(list->add_ignore, sizeof list->add_ignore[0] * (size_t) (list->add_ignore_count + 1));
	if (ignore == NULL) {
	    log_warn("%s: Failed to extend add_ignore table: %s", list->name, strerror(errno));
	    goto err;
	}

	list->add_ignore = ignore;
	list->add_ignore[list->add_ignore_count].from = from;
	list->add_ignore[list->add_ignore_count].to = to;
	list->add_ignore_count++;

	if (debug)
	    log_debug("%s: Sub for [C_%08x] ... [C_%08x] will be ignored", list->name, from, to);

    } else {
	struct sbdb_chunk_ignore *ignore;

	ignore = realloc(list->sub_ignore, sizeof list->sub_ignore[0] * (size_t) (list->sub_ignore_count + 1));
	if (ignore == NULL) {
	    log_warn("%s: Failed to extend sub_ignore table: %s", list->name, strerror(errno));
	    goto err;
	}

	list->sub_ignore = ignore;
	list->sub_ignore[list->sub_ignore_count].from = from;
	list->sub_ignore[list->sub_ignore_count].to = to;
	list->sub_ignore_count++;

	log_debug("%s: Add for [C_%08x] ... [C_%08x] will be ignored", list->name, from, to);

    }

    /*
     * Apply this ignore list
     */
    for (chunk_num = from; chunk_num <= to; chunk_num++) {
	struct sbdb_chunk *chunk = get_chunk(list, chunk_num);

	if (chunk == NULL)
	    continue;

	if (type == sb_add) {
	    while (chunk->chunk_add_first != NULL)
		free_chunk_add(chunk, chunk->chunk_add_first);
	} else {
	    while (chunk->chunk_sub_first != NULL)
		free_chunk_sub(chunk, chunk->chunk_sub_first);
	}
    }

    return 0;

err:
    return -1;
}

int sbdb_chunk_is_ignored(const struct sbdb_list *list, const int type, const uint32_t chunk_num)
{
    const int count = (type == sb_add) ? list->add_ignore_count : list->sub_ignore_count;
    const struct sbdb_chunk_ignore *ignore = (type == sb_add) ? list->add_ignore : list->sub_ignore;
    int i;

    for (i = 0; i < count; i++) {
	if (chunk_num >= ignore[i].from && chunk_num <= ignore[i].to)
	    return true;
    }

    return false;
}

#define safe_set(l, what) do {                                          \
        if (strcmp((l)->what, what) != 0) {                             \
            free((l)->what);                                            \
            (l)->what = strdup(what);                                   \
            if ((l)->what == NULL) {                                    \
                log_crit("%s: Failed to allocate %s : %s", "" # what, (l)->name, strerror(errno)); \
                return -1;                                              \
            }                                                           \
        }                                                               \
    } while (0)

int sbdb_set_url(struct sbdb_list *list, const char *url)
{
    safe_set(list, url);
    return 0;
}

int sbdb_set_header(struct sbdb_list *list, const char *header)
{
    safe_set(list, header);
    return 0;
}
