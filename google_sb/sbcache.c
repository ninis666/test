
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sbcache.c 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#define PFX "[SBCACHE] "
#include "logger.h"
#include "buffer.h"
#include "sbcache.h"
#include "util.h"

static int get_younger(const char *root_dir, const char *prefix, const char *name, const time_t timestamp, char *found, const size_t found_max, time_t * found_timestamp)
{
    DIR *dir;
    time_t first;
    char pattern[NAME_MAX];
    size_t pattern_len;

    pattern_len = (size_t) snprintf(pattern, sizeof pattern, "%s%s_", prefix, name);
    if (pattern_len >= sizeof pattern) {
	log_crit("Too long prefix / name : <%s> / <%s>", prefix, name);
	return -1;
    }

    dir = opendir(root_dir);
    if (dir == NULL)
	goto not_found;

    found[0] = 0;
    first = LONG_MAX;
    for (;;) {
	struct dirent entry;
	struct dirent *res;
	time_t t;
	int err;
	char *ptr;

	err = readdir_r(dir, &entry, &res);
	if (err != 0) {
	    log_crit("Failed to readdir on <%s> : %s", root_dir, strerror(err));
	    goto closedir_err;
	}

	if (res == NULL)
	    break;

	if (strncmp(entry.d_name, pattern, pattern_len) != 0)
	    continue;

	t = strtol(entry.d_name + pattern_len, &ptr, 0);
	if (*ptr != 0)
	    continue;

	if (t > timestamp && t < first) {
	    if ((size_t) snprintf(found, found_max, "%s/%s", root_dir, entry.d_name) >= found_max) {
		log_crit("Too small buffer !");
		goto closedir_err;
	    }
	    first = t;
	}
    }

    closedir(dir);

    if (found[0] == 0)
	goto not_found;

    *found_timestamp = first;
    return true;

not_found:
    return false;

closedir_err:
    closedir(dir);
    return -1;
}

static int get_latest(const char *root_dir, const char *prefix, const char *name, char *found, const size_t found_max, time_t * found_timestamp)
{
    DIR *dir;
    long latest;
    char pattern[NAME_MAX];
    size_t pattern_len;

    dir = opendir(root_dir);
    if (dir == NULL)
	goto not_found;

    pattern_len = (size_t) snprintf(pattern, sizeof pattern, "%s%s_", prefix, name);
    if (pattern_len >= sizeof pattern) {
	log_crit("Too long prefix / name : <%s> / <%s>", prefix, name);
	return -1;
    }

    found[0] = 0;
    latest = -1;
    for (;;) {
	struct dirent entry;
	struct dirent *res;
	time_t timestamp;
	int err;
	char *ptr;

	err = readdir_r(dir, &entry, &res);
	if (err != 0) {
	    log_crit("Failed to readdir on <%s> : %s", root_dir, strerror(err));
	    goto closedir_err;
	}

	if (res == NULL)
	    break;

	if (strncmp(entry.d_name, pattern, pattern_len) != 0)
	    continue;

	timestamp = strtol(entry.d_name + pattern_len, &ptr, 0);
	if (*ptr != 0)
	    continue;

	if (timestamp > latest) {
	    if ((size_t) snprintf(found, found_max, "%s/%s", root_dir, entry.d_name) >= found_max) {
		log_crit("Too small buffer !");
		goto closedir_err;
	    }
	    latest = timestamp;
	}
    }

    closedir(dir);

    if (latest < 0)
	goto not_found;

    *found_timestamp = latest;
    return true;

not_found:
    log_debug("No valid <%s/%s*> found", root_dir, pattern);
    return false;

closedir_err:
    closedir(dir);
    return -1;
}

int sbcache_dump_find_younger(const char *name, const time_t timestamp, char *found, const size_t found_max, time_t * found_timestamp)
{
    return get_younger(SBCACHE_DEFAULT_ROOT_DIR, SBCACHE_DEFAULT_DUMP_PREFIX, name, timestamp, found, found_max, found_timestamp);
}

int sbcache_dump_find_latest(const char *name, char *found, const size_t found_max, time_t * found_timestamp)
{
    return get_latest(SBCACHE_DEFAULT_ROOT_DIR, SBCACHE_DEFAULT_DUMP_PREFIX, name, found, found_max, found_timestamp);
}

static ssize_t do_write(int fd, const void *data, const size_t data_size)
{
    const char *ptr = data;
    const char *end = ptr + data_size;

    while (ptr != end) {
	ssize_t n;

	n = write(fd, ptr, (size_t) (end - ptr));
	if (n < 0)
	    return -1;

	ptr += n;
    }

    return end - (char *) data;
}

static ssize_t do_read(int fd, void *data, const size_t data_size)
{
    char *ptr = data;
    const char *end = ptr + data_size;

    while (ptr != end) {
	ssize_t n;

	n = read(fd, ptr, (size_t) (end - ptr));
	if (n < 0)
	    return -1;

	/* If end of file occurs, returns 0 */
	if (n == 0)
	    return 0;

	ptr += n;
    }

    return end - (char *) data;
}

int sbcache_dump_open(const char *name, const time_t timestamp, char **dump_name)
{
    char path[PATH_MAX];
    const char *root_dir = SBCACHE_DEFAULT_ROOT_DIR;
    const char *prefix = SBCACHE_DEFAULT_DUMP_PREFIX;
    int fd;

    if ((size_t) snprintf(path, sizeof path, "%s/%s%s_%ld", root_dir, prefix, name, timestamp) >= sizeof path) {
	log_crit("Too long root_dir / prefix : <%s> / <%s>", root_dir, prefix);
	goto err;
    }

    fd = open_mkdir(path);
    if (fd < 0)
	goto err;

    if (dump_name != NULL) {
	*dump_name = strdup(path);
	if (*dump_name == NULL) {
	    log_crit("Failed to allocate dump_name : %s", strerror(errno));
	    goto close_err;
	}
    }

    log_debug("Dump file create <%s>", path);
    return fd;

close_err:
    close(fd);
err:
    return -1;
}

int sbcache_dump_save(int fd, tbuffer * buffer)
{
    if (lseek(fd, 0, SEEK_END) == (off_t) - 1) {
	log_crit("Failed to seek to end of dump file: %s", strerror(errno));
	goto err;
    }

    if (do_write(fd, &buffer->buf_size, sizeof buffer->buf_size) < 0) {
	log_warn("Can't write size into dump file : %s", strerror(errno));
	goto err;
    }

    if (do_write(fd, buffer->buf, buffer->buf_size) < 0) {
	log_warn("Failed to write into dump filr : %s", strerror(errno));
	goto err;
    }

    return 0;

err:
    return -1;
}

int sbcache_dump_load_next(int fd, tbuffer * buffer)
{
    __typeof__(buffer->buf_size) s;
    ssize_t n;

    buffer_reset(buffer);

    n = do_read(fd, &s, sizeof s);
    if (n < 0) {
	log_warn("Cant read size: %s", strerror(errno));
	goto err;
    }
    if (n == 0)
	return false;

    if (buffer_extend(buffer, s) != STATUS_SUCCESS) {
	log_crit("Failed to extend buffer to <%zd>", s);
	goto err;
    }

    n = do_read(fd, buffer->buf, s);
    if (n <= 0) {
	log_warn("Cant read data : %s", strerror(errno));
	goto reset_err;
    }

    return true;

reset_err:
    buffer_reset(buffer);
err:
    return -1;
}

ssize_t sbcache_dump_to_buffer(const char *dumpfile, tbuffer * buffer)
{
    int fd;
    struct stat st;

    if (stat(dumpfile, &st) < 0) {
	log_warn("Failed to stat dump file <%s> : %s", dumpfile, strerror(errno));
	goto err;
    }

    if (st.st_size == 0) {
	log_warn("Trying to load an empty dump file <%s>", dumpfile);
	goto err;
    }

    fd = open(dumpfile, O_RDONLY);
    if (fd < 0) {
	log_warn("Failed to open <%s> dumpfile : %s", dumpfile, strerror(errno));
	goto err;
    }

    buffer_reset(buffer);

    if (buffer_extend(buffer, (size_t) st.st_size) != STATUS_SUCCESS) {
	log_crit("Failed to extend buffer to <%zd>", st.st_size);
	goto close_err;
    }

    if (do_read(fd, buffer->buf, (size_t) st.st_size) <= 0) {
	log_warn("Cant read data : %s", strerror(errno));
	goto reset_err;
    }

    close(fd);
    return st.st_size;

reset_err:
    buffer_reset(buffer);
close_err:
    close(fd);
err:
    return -1;
}

int sbcache_buffer_to_dump(const char *name, const time_t timestamp, const tbuffer * buffer)
{
    int fd;

    fd = sbcache_dump_open(name, timestamp, NULL);
    if (fd < 0)
	goto err;

    if (do_write(fd, buffer->buf, buffer->buf_size) < 0) {
	log_crit("Cant write data: %s", strerror(errno));
	goto close_err;
    }

    close(fd);
    return 0;

close_err:
    close(fd);
err:
    return -1;
}
