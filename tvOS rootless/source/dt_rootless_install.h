#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Install pre-transformed payload using the same path-manifest TSV as postverify. */
int dt_rootless_install_transformed_tree(NSString *payloadRoot, NSString *manifestPath,
                                         void (^log)(NSString *), NSString **errOut);

/** Rewrite dpkg database paths to /var/jb and Arch to appletvos-arm64-rootless. */
int dt_rootless_rewrite_dpkg_db(NSString *jbroot, void (^log)(NSString *), NSString **errOut);

/** Install OpenSSH add-on packages already present under payloadRoot. */
int dt_rootless_install_openssh_addon(NSString *payloadRoot, void (^log)(NSString *), NSString **errOut);

/**
 * Run KEEP prep_bootstrap.sh (account finalize + uialert password UI + pw usermod).
 * FRESH: required while $JBROOT/prep_bootstrap.sh exists; failure must block commit.
 * REUSE: if script absent (deleted after successful FRESH), skip = PASS (intended).
 * If script still present on REUSE, run it (incomplete prior finalize).
 */
int dt_rootless_run_prep_bootstrap(void (^log)(NSString *), NSString **errOut);

/**
 * Ask launchd to start one trusted, inert child and require the child-side
 * systemhook constructor to acknowledge a successful jbserver check-in.
 * This is current-boot validation only; it does not enable userspace reboot.
 */
int dt_rootless_run_current_boot_runtime_probe(void (^log)(NSString *), NSString **errOut);

/**
 * Post-verify JBROOT against packaged path manifest (RELATIVE_PATH / KIND / SYMLINK_TARGET).
 * Covers files, directories, symlinks, and Mach-O SHA rows — not Mach-Os only.
 */
int dt_rootless_postverify_payload_tree(NSString *jbroot, NSString *manifestPath,
                                        void (^log)(NSString *), NSString **errOut);

#ifdef __cplusplus
}
#endif
