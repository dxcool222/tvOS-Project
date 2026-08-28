#pragma once

#include <stddef.h>

#define DT_R24_RUNTIME_TRACE_PATH "/private/var/jb/.r24_runtime_trace"
#define DT_R24_RUNTIME_TRACE_MAX_BYTES (32u * 1024u * 1024u)

/*
 * Cross-process R24 diagnostics.  Every event is emitted to unified logging
 * and appended as one line to the current /var/jb runtime trace.  The app
 * continuously relays that file to macOS Console during bring-up.
 */
int dt_r24_trace_event(const char *component, const char *event, int rc,
                       int error_number, const char *detail);

