/*
 * R24 CBR: ElleKit MSHookFunction API shape, implemented via litehook
 * (Theos AppleTVOS16.4.sdk). Not Cydia Substrate.
 */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int dt_cbr_MSHookFunction(void *symbol, void *replace, void **result);

#ifdef __cplusplus
}
#endif
