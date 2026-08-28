#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// misaka/J _offsets_init @ 0x10000a54c — tvOS 16.4+ / iOS 16.4+ branch (>16.3.1).
/// Full 88-field table for post-kopen jailbreak; do_fun uses proc/ucred subset only.
typedef struct {
    uint32_t off_p_ro_p_csflags;
    uint32_t off_p_ro_p_ucred;
    uint32_t off_p_ro_pr_proc;
    uint32_t off_p_ro_pr_task;
    uint32_t off_p_ro_t_flags_ro;
    uint32_t off_task_itk_space;
    uint32_t off_task_t_flags;
    uint32_t off_u_cr_label;
    uint32_t off_u_cr_posix;
    uint32_t off_cr_uid;
    uint32_t off_cr_ruid;
    uint32_t off_cr_svuid;
    uint32_t off_cr_ngroups;
    uint32_t off_cr_groups;
    uint32_t off_cr_rgid;
    uint32_t off_cr_svgid;
    uint32_t off_cr_gmuid;
    uint32_t off_cr_flags;
    uint32_t off_fd_ofiles;
    uint32_t off_fd_cdir;
    uint32_t off_fp_glob;
    uint32_t off_fg_data;
    uint32_t off_fg_flag;
    uint32_t off_specinfo_si_flags;
    uint32_t off_vnode_v_ncchildren_tqh_first;
    uint32_t off_vnode_v_ncchildren_tqh_last;
    uint32_t off_vnode_v_nclinks_lh_first;
    uint32_t off_vnode_v_iocount;
    uint32_t off_vnode_v_usecount;
    uint32_t off_vnode_v_flag;
    uint32_t off_vnode_v_kusecount;
    uint32_t off_vnode_v_references;
    uint32_t off_vnode_v_lflag;
    uint32_t off_vnode_v_owner;
    uint32_t off_vnode_v_cred;
    uint32_t off_vnode_v_writecount;
    uint32_t off_vnode_v_type;
    uint32_t off_vnode_v_id;
    uint32_t off_vnode_vu_ubcinfo;
    uint32_t off_vnode_v_name;
    uint32_t off_vnode_v_mount;
    uint32_t off_vnode_v_data;
    uint32_t off_vnode_v_parent;
    uint32_t off_vnode_v_label;
    uint32_t off_mount_mnt_data;   // IDA _vfs_fsprivate @ 0x8F8 (=2296); use DT_BAKED_MOUNT_FSPRIVATE in remount path
    uint32_t off_mount_mnt_fsowner;
    uint32_t off_mount_mnt_fsgroup;
    uint32_t off_mount_mnt_flag;
    uint32_t off_ipc_space_is_table;
    uint32_t off_ubc_info_cs_blobs;
    uint32_t off_ubc_info_cs_add_gen;
    uint32_t off_pmap_cs_code_directory_ce_ctx;
    uint32_t off_pmap_cs_code_directory_der_entitlements_size;
    uint32_t off_pmap_cs_code_directory_trust;
    uint32_t off_ipc_entry_ie_object;
    uint32_t off_ipc_object_io_bits;
    uint32_t off_ipc_object_io_references;
    uint32_t off_ipc_port_ip_kobject;
    uint32_t off_cs_blob_csb_cdhash;
    uint32_t off_cs_blob_csb_flags;
    uint32_t off_cs_blob_csb_teamid;
    uint32_t off_cs_blob_csb_validation_category;
    uint32_t off_namecache_nc_child_tqe_prev;
    uint32_t off_p_list_le_prev;
    uint32_t off_p_proc_ro;
    uint32_t off_p_ppid;
    uint32_t off_p_original_ppid;
    uint32_t off_p_pgrpid;
    uint32_t off_p_uid;
    uint32_t off_p_gid;
    uint32_t off_p_ruid;
    uint32_t off_p_rgid;
    uint32_t off_p_svuid;
    uint32_t off_p_svgid;
    uint32_t off_p_sessionid;
    uint32_t off_p_puniqueid;
    uint32_t off_p_pid;
    uint32_t off_p_flag;
    uint32_t off_p_pfd;
    uint32_t off_p_textvp;
    uint32_t off_p_name;
    uint32_t off_namecache_nc_dvp;
    uint32_t off_namecache_nc_vp;
    uint32_t off_namecache_nc_hashval;
    uint32_t off_namecache_nc_name;
    uint32_t off_cs_blob_csb_pmap_cs_entry;
} dt_misaka_offsets_t;

extern dt_misaka_offsets_t g_misaka_offsets;

/// Same as J _offsets_init() for tvOS 16.5 (16.4+ branch).
void dt_misaka_offsets_init(void);

/// J get_vm_kernel_link_addr @ 0x10000ee50
uint64_t dt_get_vm_kernel_link_addr(void);

#ifdef __cplusplus
}
#endif
