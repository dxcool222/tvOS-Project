#pragma once

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Load CDHashes from bundled ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv via existing trust APIs. */
int dt_rootless_load_trust_manifest(NSString *manifestPath, void (^log)(NSString *), NSString **errOut);

/** Upload exactly one live CDHash under a dedicated trustcache UUID. */
int dt_rootless_load_single_trust_path(NSString *path, const unsigned char uuid[16],
                                      void (^log)(NSString *), NSString **errOut);

#ifdef __cplusplus
}
#endif
