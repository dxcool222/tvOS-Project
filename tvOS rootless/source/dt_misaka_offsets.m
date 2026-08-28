#import "dt_misaka_offsets.h"
#import <string.h>
#import <sys/sysctl.h>

dt_misaka_offsets_t g_misaka_offsets;

uint64_t dt_get_vm_kernel_link_addr(void)
{
    char kv[512] = {0};
    size_t len = sizeof(kv);
    if (sysctlbyname("kern.version", kv, &len, NULL, 0) != 0)
        return 0xfffffff007004000ULL;

    // J: T8103/T8112 use 0xfffffe0007004000; Apple TV T8010 uses 0xfffffff007004000
    if (strstr(kv, "T8103") || strstr(kv, "T8112") || strstr(kv, "T8120"))
        return 0xfffffe0007004000ULL;
    return 0xfffffff007004000ULL;
}

void dt_misaka_offsets_init(void)
{
    // misaka/J _offsets_init @ 0x10000a54c — iOS/tvOS 16.4+ branch (>16.3.1)
    g_misaka_offsets = (dt_misaka_offsets_t){
        .off_p_ro_p_csflags = 28,
        .off_p_ro_p_ucred = 32,
        .off_p_ro_pr_proc = 0,
        .off_p_ro_pr_task = 8,
        .off_p_ro_t_flags_ro = 120,
        .off_task_itk_space = 768,
        .off_task_t_flags = 976,
        .off_u_cr_label = 120,
        .off_u_cr_posix = 24,
        .off_cr_uid = 0,
        .off_cr_ruid = 4,
        .off_cr_svuid = 8,
        .off_cr_ngroups = 12,
        .off_cr_groups = 16,
        .off_cr_rgid = 80,
        .off_cr_svgid = 84,
        .off_cr_gmuid = 88,
        .off_cr_flags = 92,
        .off_fd_ofiles = 0,
        .off_fd_cdir = 32,
        .off_fp_glob = 16,
        .off_fg_data = 56,
        .off_fg_flag = 16,
        .off_specinfo_si_flags = 16,
        .off_vnode_v_ncchildren_tqh_first = 48,
        .off_vnode_v_ncchildren_tqh_last = 56,
        .off_vnode_v_nclinks_lh_first = 64,
        .off_vnode_v_iocount = 100,
        .off_vnode_v_usecount = 96,
        .off_vnode_v_flag = 84,
        .off_vnode_v_kusecount = 92,
        .off_vnode_v_references = 91,
        .off_vnode_v_lflag = 88,
        .off_vnode_v_owner = 104,
        .off_vnode_v_cred = 152,
        .off_vnode_v_writecount = 176,
        .off_vnode_v_type = 112,
        .off_vnode_v_id = 116,
        .off_vnode_vu_ubcinfo = 120,
        .off_vnode_v_name = 184,
        .off_vnode_v_mount = 216,
        .off_vnode_v_data = 224,
        .off_vnode_v_parent = 192,
        .off_vnode_v_label = 232,
        .off_mount_mnt_data = 2296,
        .off_mount_mnt_fsowner = 2496,
        .off_mount_mnt_fsgroup = 2500,
        .off_mount_mnt_flag = 112,
        .off_ipc_space_is_table = 32,
        .off_ubc_info_cs_blobs = 80,
        .off_ubc_info_cs_add_gen = 44,
        .off_pmap_cs_code_directory_ce_ctx = 456,
        .off_pmap_cs_code_directory_der_entitlements_size = 472,
        .off_pmap_cs_code_directory_trust = 476,
        .off_ipc_entry_ie_object = 0,
        .off_ipc_object_io_bits = 0,
        .off_ipc_object_io_references = 4,
        .off_ipc_port_ip_kobject = 72,
        .off_cs_blob_csb_cdhash = 88,
        .off_cs_blob_csb_flags = 32,
        .off_cs_blob_csb_teamid = 136,
        .off_cs_blob_csb_validation_category = 176,
        .off_namecache_nc_child_tqe_prev = 16,
        .off_p_list_le_prev = 8,
        .off_p_proc_ro = 24,
        .off_p_ppid = 32,
        .off_p_original_ppid = 36,
        .off_p_pgrpid = 40,
        .off_p_uid = 44,
        .off_p_gid = 48,
        .off_p_ruid = 52,
        .off_p_rgid = 56,
        .off_p_svuid = 60,
        .off_p_svgid = 64,
        .off_p_sessionid = 68,
        .off_p_puniqueid = 72,
        .off_p_pid = 96,
        .off_p_flag = 0x25C,
        .off_p_pfd = 248,
        .off_p_textvp = 1352,
        .off_p_name = 1401,
        .off_namecache_nc_dvp = 72,
        .off_namecache_nc_vp = 80,
        .off_namecache_nc_hashval = 88,
        .off_namecache_nc_name = 96,
        .off_cs_blob_csb_pmap_cs_entry = 0xFFFF,
    };
}
