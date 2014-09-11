
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sb.h 594 2014-02-07 09:41:45Z njagabar $
 * @package		consumerd
 */

#ifndef __SB_H__
# define __SB_H__

# ifndef SB_DEFAULT_KEY
#  define SB_DEFAULT_KEY    "ABQIAAAA6XiHDpcsqAh_lkCa-i9IhRSrjImo17bplOTDZGGN7zpi_Wuk3w"
# endif

# define SB_DEFAULT_URL    "http://safebrowsing.clients.google.com/safebrowsing"
# define SB_DEFAULT_CLIENT "api"
# define SB_DEFAULT_APPVER "1.5.2"
# define SB_DEFAULT_PVER   "2.2"

/**
 * Initialize a new list and load it with currently saved dump files
 *
 * - name: the name of the list
 * - key: a registred key on google GSB API
 * - client_ver: an arbitrary string used to name the client
 * - api_ver: the expected GSB API. If set to NULL, SB_DEFAULT_PVER will be used
 * - url: the URL of GSB API. If set to NULL, SB_DEFAULT_URL will be used
 *
 * return values:
 * - NULL if an error occured
 * - The newly initialized list ; should be freed with sb_free
 */
struct sbdb_list *sb_init(const char *name, const char *key, const char *client_ver, const char *api_ver, const char *url);

/**
 * Download updates from GSB, save it in dump file and update host lists
 *
 * - list: the list to update
 * - now:  a timestamp used to suffix the dump file name
 * - host_update: if set to false, host lists update is not allowed
 * - dump_name: will contain the name of the dump file. It should be free by the caller
 *
 * return value:
 * < 0 if and error occured
 *   0 if the list was not updated
 * > 0 if the list was updated
 * 
 */
int sb_downloads(struct sbdb_list *list, const time_t now, const int host_update, char **dump_name);

/**
 * Create a buffer loaded with a dump file
 *
 * - dumpfile: the name of the dump file
 *
 * return value:
 * - NULL if an error occured
 * - The newly created buffer. It should be freed with buffer_free
 */
tbuffer *sb_dump_to_buffer(const char *dumpfile);

/**
 * Write a buffer on a dump file. It will then apply de dumped data on the list
 *
 * - list: the list
 * - timestamp: the timestamp to suffix the dump file name
 * - buffer: the buffer to write
 *
 */
int sb_buffer_to_dump(struct sbdb_list *list, const time_t timestamp, tbuffer * buffer, const int host_update);

/**
 * Perform lookups on the list to check if an url is contained
 *
 * - list: the list to check
 * - url:  the URL to check for
 * - host_update: if set to false, host lists update is not allowed
 */
int sb_lookup(struct sbdb_list *list, const char *url);

/**
 * Change parameters used to initialize a list
 *
 * - key: a registred key on google GSB API
 * - client_ver: an arbitrary string used to name the client
 * - api_ver: the expected GSB API. If set to NULL, SB_DEFAULT_PVER will be used
 */
int sb_set_param(struct sbdb_list *list, const char *key, const char *client_ver, const char *api_ver);

/**
 * Change the GSB API URL
 *
 * - url: the URL of GSB API. If set to NULL, SB_DEFAULT_URL will be used
 */
int sb_set_url(struct sbdb_list *list, const char *url);

int sb_list(thttpreq_ctx * http, const char *url, const char *header, char **list, const int list_max);
void sb_set_debug(const int new_debug);

#endif
