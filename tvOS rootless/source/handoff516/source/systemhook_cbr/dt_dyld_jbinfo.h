#pragma once
#include <stdbool.h>
#include <stdint.h>
#define DYLD_STATE_CHECKED_IN 1
struct dyld_jbinfo {
	uint64_t state;
	char *jbRootPath;
	char *bootUUID;
	char *sandboxExtensions;
	bool fullyDebugged;
	char data[];
};
