#pragma once

#import <Foundation/Foundation.h>
#import <signatures.h>
#import <uuid/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Phys-rw PTE handoff only (no ucred / bootstrap). Requires active kfd + baked tvOS offsets.
int dt_build_physrw_handoff_only(void (^log)(NSString *line));

/// BUILD102716/102719: existing physrw-ready predicate (no cold PTE init).
bool dt_phys716_phys_ready(void);

/// BUILD102719: syscall-only APFS MNT_UPDATE (isolated from build47 patch chain).
/// mount_mode bit0=1 → RO update request (DT_APFS_MOUNT_FILESYSTEM=1); bit0=0 → RW update request.
int dt102719_syscall_apfs_mnt_update(const char *mnton, uint32_t mount_mode, void (^log)(NSString *line));

/// BUILD102720: intentional RO→RW using BUILD102719-proven dt_apfs_mount_args shape (MNT_UPDATE only).
int dt102720_syscall_apfs_mnt_update_rw(const char *mnton, void (^log)(NSString *line));

/// BUILD102720: RO restore via upstream Dopamine shape (MNT_UPDATE|MNT_RDONLY, dt_hfs_mount_args).
int dt102720_syscall_apfs_mnt_update_ro_restore(const char *mnton, void (^log)(NSString *line));

/// Build 696: read-modify-write single byte via physwrite32 (after handoff). Preserves adjacent bytes in the aligned word.
int dt_phys_write8_va_rm(uint64_t va, uint8_t val, const char *tag, void (^log)(NSString *line));

/// Build 696: read single byte from kernel VA (kread32-aligned word).
int dt_phys_read8_va(uint64_t va, uint8_t *out, void (^log)(NSString *line));

/// Build 24: reversible physwrite32 on self ucred cr_uid (after handoff). Does not change getuid().
int dt_build_phys_cred_smoke(uint64_t proc, void (^log)(NSString *line));

/// Build 25: phys-rw root cred patch (after handoff + build24 smoke). Success leaves getuid()==0.
int dt_build_phys_root_esc(uint64_t proc, void (^log)(NSString *line));

/// Build 26: kalloc_pt + trustcache list enumerate + single cdhash upload smoke (after root).
int dt_build_trustcache_smoke(void (^log)(NSString *line));

/// G52 read-only: best CD hash from Mach-O code directory at path. Returns 0 on success.
int dt_macho_best_cdhash_from_path(const char *path, cdhash_t out);

/// G52 read-only: 64-char hex CD hash for logs.
NSString *dt_cdhash_hex_string(const cdhash_t hash);

/// G52 read-only: kernel trustcache membership (needs active exploit primitives).
bool dt_cdhash_trustcached(const cdhash_t hash);

/// Build 73 G5: upload missing CDHashes via trustcache_file_upload (requires root + phys primitives).
/// uploadedOut/skippedOut may be NULL. Returns 0 on success (including all-already-cached).
int dt_trustcache_upload_cdhashes(const cdhash_t *hashes, uint32_t count,
                                  uint32_t *uploadedOut, uint32_t *skippedOut);

/// Build 102.3.3 G5 final batch: upload every CDHash in one blob (no skip-if-cached).
int dt_trustcache_upload_cdhashes_force(const cdhash_t *hashes, uint32_t count,
                                        uint32_t *uploadedOut);

/// BUILD102722: one multi-entry trustcache_file_v1 upload with caller-supplied UUID.
int dt_trustcache_upload_batch_cdhashes(const cdhash_t *hashes, uint32_t count,
                                        const uuid_t uuid, uint32_t *uploadedOut);

/// Build 27 / 89: gid 0 + unsandbox (mac_label slot 0) + CS_PLATFORM_BINARY (after build 26).
int dt_build_privesc_smoke(uint64_t proc, void (^log)(NSString *line));

/// Build 97 §36.2 Option A: gid0 + platformize; preserve slot0 (no mac_label_set -1) for EXT consume.
int dt_build97_privesc_preserve_slot0(uint64_t proc, void (^log)(NSString *line));

/// Build 89: log Seatbelt MAC label slots 0/1 for current pid (diag + pre-G5 spawn).
void dt_build89_log_mac_label_slots(const char *when);

/// Build 99 §42.9: full proc→ucred→label→slot0/1 chain immediately pre-consume (diag only).
/// Mirrors kernel path 532C68→532930→82A648 for live BP compare (5510E8/532C94/82A6B4).
void dt_build99_log_consume_chain(const char *when);

/// Build 100 §26: thread kptr → vfs_context → mirror_532C68(proc_find/ctx_proc/ctx_ucred).
/// Returns 0 on successful log, negative on resolution failure.
int dt_build100_log_ctx_proof(void (^ _Nullable log)(NSString *line));

/// Build 102583 Probe A: mirror 532930 slot0 profile pointer for pid (532C68 path).
int dt_mirror_profile_ptr_for_pid(pid_t pid, uint64_t *profileOut);

/// Graph incomplete (container/vol_sb null or os.update graft failed) — no kernel remount patches (build67).
#define DT_BUILD47_ERR_GRAPH_INCOMPLETE (-62)

/// True only after dt_build_remount_smoke completes staged remount.
/// On os.update roots, success is case5 OK plus statfs("/") RW; / write probe is skipped.
bool dt_build_rootful_remount_ok(void);

/// Build 38: APFS root mount discovery log only (no patches, no mount, no / write).
int dt_build_remount_smoke(void (^log)(NSString *line));

/// Build 95 G5: P1 @ sandbox 539C78 (IDA §27.1, com.apple.security.sandbox:__text r-x).
/// Uses kfd sem_open kwrite (not physwrite — build94 hung on __text). Requires open kfd + phys handoff.
int dt_build95_apply_sandbox_op129_p1(void (^log)(NSString *line));

#import "stubs/dt_physrw_log.h"

#ifdef __cplusplus
}
#endif
