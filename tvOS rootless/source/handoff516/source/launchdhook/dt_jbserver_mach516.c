#include <dlfcn.h>
#include <libjailbreak/jbserver.h>
#include <mach/mach.h>
#include <bsm/audit.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dt_runtime_trace.h"

extern int fileport_makefd(mach_port_t port);

typedef kern_return_t (*dt_mach_msg_send_fn)(mach_msg_header_t *);
static dt_mach_msg_send_fn dt516_mach_msg_send;

__attribute__((constructor)) static void dt516_jbserver_mach_init(void)
{
    dt516_mach_msg_send = (dt_mach_msg_send_fn)dlsym(RTLD_DEFAULT, "mach_msg_send");
}

int systemwide_process_checkin(audit_token_t *processToken, char **rootPathOut,
    char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);
int systemwide_fork_fix(audit_token_t *parentToken, uint64_t childPid);
int systemwide_trust_file(audit_token_t *processToken, int rfd, struct siginfo *siginfo,
    size_t siginfoSize);
bool systemwide_domain_allowed(audit_token_t clientToken);

int jbserver_send_mach_reply(mach_msg_header_t *hdr, void *replyData)
{
    kern_return_t kr = -1;

    if (replyData && MACH_PORT_VALID(hdr->msgh_remote_port) &&
        MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) != 0) {
        struct jbserver_mach_msg_reply *reply =
            (struct jbserver_mach_msg_reply *)replyData;

        uint32_t bits = MACH_MSGH_BITS_REMOTE(hdr->msgh_bits);
        if (bits == MACH_MSG_TYPE_COPY_SEND)
            bits = MACH_MSG_TYPE_MOVE_SEND;

        reply->msg.hdr.msgh_bits = MACH_MSGH_BITS(bits, 0);
        reply->msg.hdr.msgh_remote_port = hdr->msgh_remote_port;
        reply->msg.hdr.msgh_local_port = 0;
        reply->msg.hdr.msgh_voucher_port = 0;
        reply->msg.hdr.msgh_id = hdr->msgh_id + 100;

        if (dt516_mach_msg_send)
            kr = dt516_mach_msg_send(&reply->msg.hdr);
        if (kr == KERN_SUCCESS) {
            hdr->msgh_remote_port = 0;
            hdr->msgh_bits = hdr->msgh_bits & ~MACH_MSGH_BITS_REMOTE_MASK;
        }
    }

    char detail[256];
    snprintf(detail, sizeof(detail), "message_id=%d remote_port=%u reply_present=%s",
        hdr ? hdr->msgh_id : -1, hdr ? hdr->msgh_remote_port : 0,
        replyData ? "YES" : "NO");
    (void)dt_r24_trace_event("JBSERVER_MACH", "REPLY_SEND", kr, 0, detail);
    return kr;
}

int jbserver_received_mach_message(audit_token_t *auditToken,
    struct jbserver_mach_msg *jbsMachMsg)
{
    int r = -1;

    char receive_detail[256];
    snprintf(receive_detail, sizeof(receive_detail), "client_pid=%d action=%llu size=%u",
        audit_token_to_pid(*auditToken), (unsigned long long)jbsMachMsg->action,
        jbsMachMsg->hdr.msgh_size);
    (void)dt_r24_trace_event("JBSERVER_MACH", "MESSAGE_RECEIVED", 0, 0,
        receive_detail);

    if (!systemwide_domain_allowed(*auditToken))
        return -1;

    uint64_t msgSize = jbsMachMsg->hdr.msgh_size;
    void *replyData = NULL;

    if (jbsMachMsg->action == JBSERVER_MACH_CHECKIN) {
        if (msgSize < sizeof(struct jbserver_mach_msg_checkin))
            return -1;

        size_t replySize = sizeof(struct jbserver_mach_msg_checkin_reply);
        replyData = malloc(replySize);
        struct jbserver_mach_msg_checkin_reply *reply =
            (struct jbserver_mach_msg_checkin_reply *)replyData;
        memset(reply, 0, replySize);

        char *jbRootPath = NULL, *bootUUID = NULL, *sandboxExtensions = NULL;
        int result = systemwide_process_checkin(
            auditToken, &jbRootPath, &bootUUID, &sandboxExtensions, &reply->fullyDebugged);

        (void)dt_r24_trace_event("JBSERVER_MACH", "CHECKIN_HANDLER_RETURN", result, 0,
            receive_detail);

        reply->base.msg.magic = jbsMachMsg->magic;
        reply->base.msg.action = jbsMachMsg->action;
        reply->base.msg.hdr.msgh_size = replySize;

        if (jbRootPath) {
            strlcpy(reply->jbRootPath, jbRootPath, sizeof(reply->jbRootPath));
            free(jbRootPath);
        }
        if (bootUUID) {
            strlcpy(reply->bootUUID, bootUUID, sizeof(reply->bootUUID));
            free(bootUUID);
        }
        if (sandboxExtensions) {
            strlcpy(reply->sandboxExtensions, sandboxExtensions,
                sizeof(reply->sandboxExtensions));
            free(sandboxExtensions);
        }

        reply->base.status = result;
        r = 0;
    } else if (jbsMachMsg->action == JBSERVER_MACH_FORK_FIX) {
        if (msgSize < sizeof(struct jbserver_mach_msg_forkfix))
            return -1;
        struct jbserver_mach_msg_forkfix *forkfixMsg =
            (struct jbserver_mach_msg_forkfix *)jbsMachMsg;

        size_t replySize = sizeof(struct jbserver_mach_msg_forkfix_reply);
        replyData = malloc(replySize);
        struct jbserver_mach_msg_forkfix_reply *reply =
            (struct jbserver_mach_msg_forkfix_reply *)replyData;
        memset(reply, 0, replySize);

        int result = systemwide_fork_fix(auditToken, forkfixMsg->childPid);

        reply->base.msg.magic = jbsMachMsg->magic;
        reply->base.msg.action = jbsMachMsg->action;
        reply->base.msg.hdr.msgh_size = replySize;
        reply->base.status = result;
        r = 0;
    } else if (jbsMachMsg->action == JBSERVER_MACH_TRUST_FILE) {
        if (msgSize < sizeof(struct jbserver_mach_msg_trust_fd))
            return -1;
        struct jbserver_mach_msg_trust_fd *trustMsg =
            (struct jbserver_mach_msg_trust_fd *)jbsMachMsg;

        size_t replySize = sizeof(struct jbserver_mach_msg_trust_fd_reply);
        replyData = malloc(replySize);
        struct jbserver_mach_msg_trust_fd_reply *reply =
            (struct jbserver_mach_msg_trust_fd_reply *)replyData;
        memset(reply, 0, replySize);

        int result = systemwide_trust_file(
            auditToken, trustMsg->fd,
            trustMsg->siginfoPopulated ? &trustMsg->siginfo : NULL,
            sizeof(struct siginfo));

        reply->base.msg.magic = jbsMachMsg->magic;
        reply->base.msg.action = jbsMachMsg->action;
        reply->base.msg.hdr.msgh_size = replySize;
        reply->base.status = result;
        r = 0;
    }

    jbserver_send_mach_reply(&jbsMachMsg->hdr, replyData);
    if (replyData)
        free(replyData);
    return r;
}
