#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DT_ROOTLESS_PATH_ERR_MAX 256

/*
 * Shared FRESH-FS install policy (device copy + HOST_SIM/M4).
 * Relative ".." is allowed only when POSIX-normalized it stays inside JBROOT.
 * Jailbreak ".." (escapes the payload root) is rejected with the same
 * "dotdot symlink REL -> TGT" string the R10 device log emitted.
 */
int dt_rootless_payload_rel_ok(const char *rel, char *err, size_t errlen);
int dt_rootless_symlink_target_ok(const char *rel, const char *tgt, char *err, size_t errlen);

/* Walk payload_root (FTW_PHYS). 0 = every entry would copy; -1 and err = first reject. */
int dt_rootless_payload_tree_install_check(const char *payload_root, char *err, size_t errlen);

/*
 * R10 device log reproduction: the pre-fix ObjC rule
 *   [tgt containsString:@".."]
 * First hit in directory walk. Does not run on the Apple TV.
 */
int dt_rootless_r10_legacy_dotdot_scan(const char *payload_root, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif
