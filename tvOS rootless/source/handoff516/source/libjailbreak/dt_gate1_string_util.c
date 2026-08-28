/*
 * Vendored from Dopamine BaseBin/systemhook/src/common.c (string_has_prefix/suffix only).
 * REFERENCE_SOURCE_SHA256=3812295be1b673548ac5d07ecb66967776038a74ebb6bbc9becd79d596ebd495 (litehook tree sibling)
 * Actual reference: systemhook/src/common.c lines 16-46
 */
#include <stdbool.h>
#include <string.h>

bool string_has_prefix(const char *str, const char *prefix)
{
	if (!str || !prefix)
		return false;

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len)
		return false;

	return strncmp(str, prefix, prefix_len) == 0;
}

bool string_has_suffix(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return false;

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len)
		return false;

	return strcmp(str + str_len - suffix_len, suffix) == 0;
}
