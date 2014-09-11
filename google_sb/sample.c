
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: sample.c 594 2014-02-07 09:41:45Z njagabar $
 * @package		GSB_API_sample
 */

#include <unistd.h>
#include <time.h>

#include "logger.h"
#include "httpreq.h"
#include "buffer.h"
#include "rwlock.h"
#include "sbdb.h"
#include "sb.h"

#define LIST_NAME "goog-malware-shavar"
//#define LIST_NAME "googpub-phish-shavar"

int main(int ac, char **av)
{
    char *dump_name;
    struct sbdb_list *list;
    int i;

    logger_init("sample");
    logger_set_drivers_console();

    list = sb_init(LIST_NAME, SB_DEFAULT_KEY, "sample_v1.0", NULL, NULL);
    if (list == NULL)
	goto err;

    log_info("%s is ready", LIST_NAME);

    for (;;) {
	const time_t now = time(NULL);

	if (sbdb_list_get_next_update(list) > now) {
	    log_info("%s is uptodate", LIST_NAME);
	    break;
	}

	log_info("%s update is requiered", LIST_NAME);
	if (sb_downloads(list, now, true, &dump_name) < 0)
	    goto free_list_err;

	if (dump_name != NULL) {
	    log_info("%s new dump generated : <%s>", LIST_NAME, dump_name);
	    free(dump_name);
	}
    }

    for (i = 1; i < ac; i++) {
	int ret;

	ret = sb_lookup(list, av[i]);
	if (ret < 0)
	    goto free_list_err;

	if (ret == false)
	    log_info("%s <%s> is not found", LIST_NAME, av[i]);
	else
	    log_info("%s <%s> is found", LIST_NAME, av[i]);
    }

    sbdb_list_free(list);
    logger_free();
    return 0;

free_list_err:
    sbdb_list_free(list);
err:
    logger_free();
    return 1;
}
