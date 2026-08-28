#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DT_ROOTLESS_POSTVERIFY_ERR_MAX 256

typedef struct {
    unsigned long n_file;
    unsigned long n_dir;
    unsigned long n_link;
    unsigned long n_macho;
    unsigned long n_fail;
    unsigned long n_type_symlink;
    unsigned long n_macho_type;
    unsigned long n_macho_sha;
    unsigned long n_missing;
    unsigned long n_extra;
    char first_err[DT_ROOTLESS_POSTVERIFY_ERR_MAX];
} dt_rootless_postverify_counts_t;

/*
 * Phase 1 (read-only) + phase 2 (install) counts. Python/ctypes reports these;
 * Python does not re-hash or re-type dest.
 */
typedef struct {
    unsigned long n_src;
    unsigned long n_src_type_mismatch;
    unsigned long n_src_tgt_mismatch;
    unsigned long n_src_macho_ok;
    unsigned long n_src_macho_fail;
    unsigned long n_symlink_install;
    unsigned long n_symlink_imm_ok;
    unsigned long n_symlink_imm_fail;
    unsigned long n_macho_imm_ok;
    unsigned long n_macho_imm_fail;
} dt_rootless_copy_counts_t;

/*
 * Phase 1: PACKED_SOURCE_VERIFY. lstat/readlink/SHA of packed tree against
 * ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv. Does not write destinations.
 */
int dt_rootless_packed_source_verify(const char *src_root, const char *manifest_path,
                                     dt_rootless_copy_counts_t *counts,
                                     char *err, size_t errlen);

/*
 * Phase 2: MANIFEST_INSTALL. Requires packed_source_verify PASS first.
 * Type authority is the manifest KIND column, not nftw typeflags.
 * Immediate dest lstat/readlink/SHA after each row. 0 = all rows verified.
 */
int dt_rootless_copy_payload_tree(const char *src_root, const char *dst_root,
                                  const char *manifest_path,
                                  dt_rootless_copy_counts_t *counts,
                                  char *err, size_t errlen);

/*
 * R12 device log reproduction. The pre-fix copier ran realpath(dest) which
 * follows a leftover dest symlink. First hit:
 *   JBROOT escape private/etc/localtime
 * HOST_SIM only. Product copy does not call this. Unreachable from FRESH_FS.
 */
int dt_rootless_r12_legacy_dest_follow_escape(const char *src_root, const char *dst_root,
                                              char *err, size_t errlen);

/* Phase 3: independent catalog postverify plus dest extra-entry census.
 * Dest may retain catalog paths, `.rootless_r4_incomplete`, and the Wall2
 * basebin handoff trio (launchdhook516 / libjailbreak / libchoma). */
int dt_rootless_postverify_payload_tree_c(const char *jbroot, const char *manifest_path,
                                          dt_rootless_postverify_counts_t *out);

#ifdef __cplusplus
}
#endif
