
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sbdb.h 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#ifndef __SBDB_H__
# define __SBDB_H__

struct sbdb_chunk_sub_table {
    uint32_t add_chunk_num;
    uint8_t prefix;
};
# define SBDB_CHUNK_SUB_TABLE_SIZE(hash_len) ((size_t)((sizeof(((struct sbdb_chunk_sub_table *)NULL)->add_chunk_num)) + (sizeof(((struct sbdb_chunk_sub_table *)NULL)->prefix) * ((size_t )hash_len))))

struct sbdb_chunk_sub {
    uint32_t host_key;

    union {
	uint32_t add_chunk_num;
	struct sbdb_chunk_sub_table *table;
    } entry;

    uint8_t add_chunk_count;
    struct sbdb_chunk_sub *chunk_sub_next;
    struct sbdb_chunk_sub *chunk_sub_prev;
};

struct sbdb_chunk_add {
    uint32_t host_key;
    uint8_t prefix_count;
    uint8_t *prefix;
    uint8_t prefix_wildcard;
    struct sbdb_chunk_add *chunk_add_next;
    struct sbdb_chunk_add *chunk_add_prev;
};
# define SBDB_CHUNK_ADD_PREFIX_SIZE(hash_len) ((size_t)(sizeof(((struct sbdb_chunk_add *)NULL)->prefix) * ((size_t )hash_len)))

enum {
    sb_add,
    sb_sub,
};

struct sbdb_chunk {
    uint32_t chunk_num;
    uint32_t hash_len;

    struct sbdb_chunk_add *chunk_add_first;
    struct sbdb_chunk_add *chunk_add_last;
    int chunk_add_added;

    struct sbdb_chunk_sub *chunk_sub_first;
    struct sbdb_chunk_sub *chunk_sub_last;
    int chunk_sub_added;

    struct sbdb_chunk *chunk_list_next;
    struct sbdb_chunk *chunk_list_prev;

    struct sbdb_chunk *chunk_hash_next;
    struct sbdb_chunk *chunk_hash_prev;
};

struct sbdb_chunk_list {
    struct sbdb_chunk *first;
    struct sbdb_chunk *last;
};

struct __attribute__ ((__packed__)) sbdb_prefix {
    size_t prefix_len;
    struct sbdb_prefix *prefix_next;
    struct sbdb_prefix *prefix_prev;
    uint8_t prefix_key;		/* Warning: this filed *MUST* be at the end ! */
};

struct sbdb_host {
    struct sbdb_host *host_next;
    struct sbdb_host *host_prev;
    uint32_t host_key;
    struct sbdb_prefix *prefix_first;
    struct sbdb_prefix *prefix_last;
};

struct sbdb_host_list {
    struct sbdb_host *host_first;
    struct sbdb_host *host_last;
};

struct sbdb_chunk_ignore {
    uint32_t from;
    uint32_t to;
};

# define SBDB_HOST_LIST_MAX_HASH 3079	/* 3079: a prime number to reduce collisions */
# define SBDB_CHUNK_LIST_MAX_HASH 3079
struct sbdb_list {
    struct rwlock lock;
    char *header;
    char *url;
    thttpreq_ctx *http;
    char *name;
    time_t last_update;
    time_t next_update;

    struct sbdb_chunk_list chunk_list;
    struct sbdb_chunk_list chunk_table[SBDB_CHUNK_LIST_MAX_HASH];

    struct sbdb_host_list host_table[SBDB_HOST_LIST_MAX_HASH];

    struct sbdb_chunk_ignore *add_ignore;
    int add_ignore_count;

    struct sbdb_chunk_ignore *sub_ignore;
    int sub_ignore_count;
};

int sbdb_list_free(struct sbdb_list *list);
struct sbdb_list *sbdb_list_new(const char *name, const char *header, const char *url);
struct sbdb_chunk *sbdb_chunk_new(struct sbdb_list *list, const uint32_t chunk_num, const uint32_t hash_len, const int type);

int sbdb_list_set_next_update(struct sbdb_list *list, const time_t when);
time_t sbdb_list_get_next_update(struct sbdb_list *list);

/* note: must be called locked */
struct sbdb_host *sbdb_host_add(struct sbdb_list *list, const uint32_t host_key);
struct sbdb_prefix *sbdb_prefix_add(struct sbdb_host *host, const uint8_t * prefix, const size_t prefix_len);
void sbdb_host_free(struct sbdb_list *list, const uint32_t host_key);

int sbdb_host_lookup(struct sbdb_list *list, const uint32_t host_key);
struct sbdb_host *sbdb_host_get(struct sbdb_list *list, const uint32_t host_key);
int sbdb_prefix_lookup(const struct sbdb_host *host, const char *path);

int sbdb_chunk_get(struct sbdb_list *list, char *res, const int res_size);

int sbdb_list_debug(struct sbdb_list *list);

ssize_t sbdb_chunk_save_sub(struct sbdb_chunk *chunk, const uint32_t host_key, const uint8_t add_chunk_count, const char *add_chunk_ptr);
ssize_t sbdb_chunk_save_add(struct sbdb_chunk *chunk, const uint32_t host_key, const uint8_t prefix_count, const char *prefix_ptr);
void sbdb_chunk_debug(const struct sbdb_list *list);
int sbdb_chunk_apply(struct sbdb_list *list, const int host_update);

void sbdb_set_debug(const int new_debug);

int sbdb_chunk_ignore_add(struct sbdb_list *list, const int type, const uint32_t from, const uint32_t to);
int sbdb_chunk_is_ignored(const struct sbdb_list *list, const int type, const uint32_t chunk_num);

int sbdb_set_url(struct sbdb_list *list, const char *url);
int sbdb_set_header(struct sbdb_list *list, const char *header);

/*
 * note: In the following functions, lock / unlock is not guaranteed.
 * We should then use sbdb_write_lock before and sbdb_write_unlock after the calls:
 * - sbdb_host_add
 * - sbdb_prefix_add
 * - sbdb_host_get
 * - sbdb_prefix_lookup
 */
static inline int sbdb_write_lock(struct sbdb_list *list)
{
    return rwlock_write_lock(&list->lock);
}

static inline int sbdb_write_unlock(struct sbdb_list *list)
{
    return rwlock_read_unlock(&list->lock);
}

static inline int sbdb_read_lock(struct sbdb_list *list)
{
    return rwlock_read_lock(&list->lock);
}

static inline int sbdb_read_unlock(struct sbdb_list *list)
{
    return rwlock_read_unlock(&list->lock);
}

#endif
