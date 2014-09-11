
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sbcache.h 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#ifndef __SBCACHE_H__
# define __SBCACHE_H__

# define SBCACHE_DEFAULT_ROOT_DIR "/var/spool/consumerd/sbcache"
# define SBCACHE_DEFAULT_DUMP_PREFIX   "dump_"

int sbcache_dump_find_younger(const char *name, const time_t timestamp, char *found, const size_t found_max, time_t * found_timestamp);

int sbcache_dump_find_latest(const char *name, char *found, const size_t found_max, time_t * found_timestamp);
int sbcache_dump_load_next(int fd, tbuffer * buffer);

int sbcache_dump_open(const char *name, const time_t timestamp, char **dump_name);
int sbcache_dump_save(int fd, tbuffer * buffer);

ssize_t sbcache_dump_to_buffer(const char *dumpfile, tbuffer * buffer);
int sbcache_buffer_to_dump(const char *name, const time_t timestamp, const tbuffer * buffer);

#endif
