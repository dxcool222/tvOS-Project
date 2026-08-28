#include "info.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * ROOTLESS-R4: get_jbroot must not treat dladdr as authority.
 * Prefer jbinfo(rootPath) when set (install-time / jbserver published real JBROOT).
 * Fallback: readlink("/var/jb") when it points at .../dopamin-tvos-102710/procursus.
 */
char *get_jbroot(void)
{
	char *info = jbinfo(rootPath);
	if (info && info[0])
		return info;

	static char fromLink[PATH_MAX];
	ssize_t n = readlink("/var/jb", fromLink, sizeof(fromLink) - 1);
	if (n > 0) {
		fromLink[n] = '\0';
		if (strstr(fromLink, "/dopamin-tvos-102710/procursus") != NULL)
			return fromLink;
	}
	return NULL;
}
