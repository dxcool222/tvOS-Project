#pragma once

#import <mach/mach.h>
#import <dispatch/dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mach_port_t serverPort;
    dispatch_semaphore_t done;
    volatile int build102737d_pte_request_reached;
    volatile int build102737d_pte_server_reply_sent;
    volatile int build102737d_pte_single_pte;
    volatile int build102737d_pte_server_dispatch_rc;
    volatile uint64_t build102737d_pte_domain;
    volatile uint64_t build102737d_pte_action;
} dt681_boomerang_info_t;

/// Dopamine DOJailbreaker.m injectLaunchdHook step 1 — host boomerang XPC server.
int dt681_boomerang_start(dt681_boomerang_info_t *infoOut,
                          void (^ _Nullable log)(NSString *line));

/// Wait for launchdhook jbclient_boomerang_done (15s timeout per BUILD102681 gate).
int dt681_boomerang_wait(dt681_boomerang_info_t *info,
                         void (^ _Nullable log)(NSString *line));

void dt681_boomerang_cleanup(dt681_boomerang_info_t *info);

#ifdef __cplusplus
}
#endif
