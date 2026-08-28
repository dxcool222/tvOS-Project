/*
 * tvOS compile prefix for Dopamine opainject private APIs.
 * BUILD102546 — AppleTVOS16.4.sdk direct compile route.
 */
#include <stdint.h>
#include <Availability.h>
#undef __API_UNAVAILABLE
#define __API_UNAVAILABLE(...)
#undef __API_AVAILABLE
#define __API_AVAILABLE(...)
#undef __TVOS_PROHIBITED
#define __TVOS_PROHIBITED
#undef __WATCHOS_PROHIBITED
#define __WATCHOS_PROHIBITED
