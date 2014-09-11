
/**
 * @author		Nisar JAGABAR <njagabar@qualys.com>
 * @copyright		Qualys Inc.
 * @version		$Id: dummy_test.c 594 2014-02-07 09:41:45Z njagabar $
 * @package		GSB_API_test
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

#include "logger.h"
#include "c_sb.h"
#include "xmalloc.h"

void do_scan(const char *url)
{
    item item;

    memset(&item, 0, sizeof item);
    item.content = (char *) url;

    if (broker_sb_scan(&item) == 0) {
	log_info("<%s> is found on <%s>", url, item.malware_name);
	free(item.malware_name);
    } else
	log_info("<%s> is not found ...", url);
}


#define PROMPT "> "
//#define PROMPT ""
int file_scan(FILE * file)
{

    for (;;) {
	char buff[1024];
	int len;

	write(STDOUT_FILENO, PROMPT, sizeof PROMPT - 1);

	if (fgets(buff, sizeof buff, file) == NULL)
	    break;
	len = strlen(buff);
	if (buff[len - 1] == '\n')
	    buff[len - 1] = 0;
	if (buff[0] == 0)
	    continue;

	do_scan(buff);
    }

    return 0;
}

static jmp_buf exit_jmp;
static void sighandler(int sig)
{
    switch (sig) {
    default:
	log_warn("Getting unexpected SIG%d", sig);
	break;

    case SIGINT:
    case SIGQUIT:
	signal(sig, sighandler);
	longjmp(exit_jmp, sig);
	break;
    }
}

int main(int ac, char **av)
{
    int i;
    unsigned long at_start = 0;
    int debug;
    int interactive;
    int asked;
    int new_mem_stat;

    logger_init("url_check");

    if (setjmp(exit_jmp) != 0)
	goto stop;

    signal(SIGINT, sighandler);
    signal(SIGQUIT, sighandler);

    debug = 0;
    for (i = 1; i < ac; i++) {
	if (strcmp(av[i], "-d") == 0)
	    debug++;
    }

    if (debug)
	logger_set_level(LOG_DEBUG);
    logger_remove_drivers_redis();
    logger_remove_drivers_syslog();
    logger_remove_drivers_file();
    logger_set_drivers_console();
    if (debug)
	broker_sb_setdebug(debug);

    at_start = mps_mem_get_counter();

    if (broker_sb_init() < 0)
	return 1;

    asked = 0;
    interactive = false;
    for (i = 1; i < ac; i++) {

	if (strcmp(av[i], "-d") == 0)
	    continue;

	if (strcmp(av[i], "-") == 0)
	    interactive = true;
	else {
	    do_scan(av[i]);
	    asked++;
	}
    }

    new_mem_stat = true;
    if (interactive || asked == 0) {

	while (!broker_sb_is_ready()) {
	    new_mem_stat = true;
	    log_info("Waiting for broker init ...");
	    sleep(1);
	}

	if (new_mem_stat) {
	    new_mem_stat = false;
	    log_info("After init, %lub used", mps_mem_get_counter() - at_start);
	}

	file_scan(stdin);
    }

stop:
    if (broker_sb_stop() < 0)
	return 1;

    log_info("After cleanup, %lub used", mps_mem_get_counter() - at_start);
    logger_free();
    return 0;
}
