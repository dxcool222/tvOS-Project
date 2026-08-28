/*
 * Gate 1 minimal watchdog domain — satisfies jbserver_global.c domain table
 * without crashreporter/JBROOT dependencies from reference jbdomain_watchdog.c.
 */
#include <libjailbreak/jbserver.h>

struct jbserver_domain gWatchdogDomain = {
	.permissionHandler = NULL,
	.actions = {
		{ 0 },
	},
};
