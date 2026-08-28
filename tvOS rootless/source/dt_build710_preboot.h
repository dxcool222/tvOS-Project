#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL dt710_copy_boot_manifest_hash(char *out, size_t outSize);
NSString *dt710_resolve_active_preboot_path(void);
NSString *dt710_resolve_preboot_root(void);
NSString *dt710_resolve_basebin_path(void);
NSString *dt710_resolve_hook_path(void);
NSString *dt710_resolve_libjailbreak_path(void);
NSString *dt710_resolve_libchoma_path(void);
NSString *dt710_resolve_systemhook_path(void);

void dt710_log_preboot_paths(void (^ _Nullable log)(NSString *line));
void dt710_log_var_jb_compat_state(void (^ _Nullable log)(NSString *line));
int dt710_stage_preboot_handoff_stack(void (^ _Nullable log)(NSString *line),
    BOOL preserve_launchdhook);
int dt710_upload_final_preboot_trust_closure(void (^ _Nullable log)(NSString *line),
    BOOL include_hook);
BOOL dt710_verify_path_coherence(void (^ _Nullable log)(NSString *line));

#ifdef __cplusplus
}
#endif
