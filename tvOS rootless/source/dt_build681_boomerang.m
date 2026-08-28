#import "dt_build681_boomerang.h"
#import "DTRunLogger.h"

#import <Foundation/Foundation.h>
#import <pthread.h>
#import <stdint.h>
#import <string.h>

#import "jbserver_boomerang.h"
#import "jbserver_domains.h"
#import <xpc/xpc.h>
#import <dlfcn.h>

typedef int (*dt681_xpc_pipe_receive_fn)(mach_port_t, xpc_object_t *);

#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
static const char *dt102737d_yesno(BOOL v)
{
    return v ? "YES" : "NO";
}

static void dt102737d_stage(NSString *line)
{
    if (!line.length)
        return;
    [[DTRunLogger shared] logStage:line];
}

static BOOL dt102737d_note_boomerang_request(dt681_boomerang_info_t *info,
    xpc_object_t xdict)
{
    if (!info || !xdict || xpc_get_type(xdict) != XPC_TYPE_DICTIONARY)
        return NO;

    uint64_t domain = xpc_dictionary_get_uint64(xdict, "jb-domain");
    uint64_t action = xpc_dictionary_get_uint64(xdict, "action");
    if (domain != JBS_DOMAIN_ROOT || action != JBS_ROOT_GET_PHYSRW)
        return NO;

    BOOL singlePTE = xpc_dictionary_get_bool(xdict, "single-pte");
    info->build102737d_pte_request_reached = 1;
    info->build102737d_pte_domain = domain;
    info->build102737d_pte_action = action;
    info->build102737d_pte_single_pte = singlePTE ? 1 : 0;
    info->build102737d_pte_server_dispatch_rc = INT32_MIN;
    info->build102737d_pte_server_reply_sent = 0;

    dt102737d_stage(@"BUILD102737D_SERVER_GET_PHYSRW_REQUEST_RECEIVED=YES");
    dt102737d_stage([NSString stringWithFormat:@"BUILD102737D_SERVER_GET_PHYSRW_DOMAIN=%llu",
        (unsigned long long)domain]);
    dt102737d_stage([NSString stringWithFormat:@"BUILD102737D_SERVER_GET_PHYSRW_ACTION=%llu",
        (unsigned long long)action]);
    dt102737d_stage([NSString stringWithFormat:@"BUILD102737D_SERVER_SINGLE_PTE_VALUE=%s",
        dt102737d_yesno(singlePTE)]);
    return YES;
}
#endif

static void dt681_boomerang_log(void (^log)(NSString *line), NSString *line)
{
    [[DTRunLogger shared] log:line];
    if (log)
        log(line);
}

static void *dt681_boomerang_thread(void *arg)
{
    dt681_boomerang_info_t *info = arg;
    dt681_xpc_pipe_receive_fn pipe_receive =
        (dt681_xpc_pipe_receive_fn)dlsym(RTLD_DEFAULT, "xpc_pipe_receive");
    while (true) {
        xpc_object_t xdict = nil;
        if (pipe_receive && !pipe_receive(info->serverPort, &xdict)) {
            BOOL build102737dPteRequest = NO;
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            build102737dPteRequest = dt102737d_note_boomerang_request(info, xdict);
#endif
            int dispatch_rc = jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict);
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
            if (build102737dPteRequest) {
                info->build102737d_pte_server_dispatch_rc = dispatch_rc;
                info->build102737d_pte_server_reply_sent = dispatch_rc == 0 ? 1 : 0;
                dt102737d_stage([NSString stringWithFormat:
                    @"BUILD102737D_SERVER_GET_PHYSRW_DISPATCH_RC=%d", dispatch_rc]);
                dt102737d_stage([NSString stringWithFormat:
                    @"BUILD102737D_PTE_SERVER_REPLY_SENT=%s",
                    dt102737d_yesno(dispatch_rc == 0)]);
            }
#endif
            if (dispatch_rc == JBS_BOOMERANG_DONE) {
                dispatch_semaphore_signal(info->done);
                break;
            }
        }
    }
    return NULL;
}

int dt681_boomerang_start(dt681_boomerang_info_t *infoOut, void (^log)(NSString *line))
{
    if (!infoOut)
        return -1;

    infoOut->serverPort = MACH_PORT_NULL;
    infoOut->done = NULL;
#if DT_BUILD_NUM == 102737 || DT_BUILD_NUM == 102738
    infoOut->build102737d_pte_request_reached = 0;
    infoOut->build102737d_pte_server_reply_sent = 0;
    infoOut->build102737d_pte_single_pte = 0;
    infoOut->build102737d_pte_server_dispatch_rc = INT32_MIN;
    infoOut->build102737d_pte_domain = 0;
    infoOut->build102737d_pte_action = 0;
#endif

    mach_port_t serverPort = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort) != KERN_SUCCESS)
        return -2;
    if (mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), serverPort);
        return -3;
    }

    infoOut->serverPort = serverPort;
    infoOut->done = dispatch_semaphore_create(0);

    pthread_t thread;
    if (pthread_create(&thread, NULL, dt681_boomerang_thread, infoOut) != 0) {
        dt681_boomerang_cleanup(infoOut);
        return -4;
    }
    pthread_detach(thread);

    dt681_boomerang_log(log, [NSString stringWithFormat:@"KCALL681_BOOMERANG_PORT_READY port=%u",
        serverPort]);
    return 0;
}

int dt681_boomerang_wait(dt681_boomerang_info_t *info, void (^log)(NSString *line))
{
    if (!info || info->serverPort == MACH_PORT_NULL || !info->done)
        return -1;

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(info->done, deadline) != 0) {
        dt681_boomerang_log(log, @"KCALL681_BOOMERANG_TIMEOUT");
        return -2;
    }

    dt681_boomerang_log(log, @"KCALL681_BOOMERANG_DONE");
    [[DTRunLogger shared] logStage:@"KCALL681_BOOMERANG_DONE"];
    return 0;
}

void dt681_boomerang_cleanup(dt681_boomerang_info_t *info)
{
    if (!info)
        return;
    if (info->serverPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), info->serverPort);
        info->serverPort = MACH_PORT_NULL;
    }
}
