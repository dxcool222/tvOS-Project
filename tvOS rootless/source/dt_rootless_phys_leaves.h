#pragma once

#include "dt_rootless_r9_product.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __OBJC__
#import <Foundation/Foundation.h>
int dt_rootless_leaf_prepare(void (^log)(NSString *line));
int dt_rootless_leaf_dep_gate(void (^log)(NSString *line));
int dt_rootless_leaf_trust_trio(void (^log)(NSString *line));
int dt_rootless_leaf_boomerang(void (^log)(NSString *line));
int dt_rootless_leaf_stash_port(void (^log)(NSString *line));
int dt_rootless_leaf_wall2_apply(void (^log)(NSString *line));
int dt_rootless_leaf_opainject1(void (^log)(NSString *line));
int dt_rootless_leaf_wall2_restore(void (^log)(NSString *line));
int dt_rootless_leaf_observe_ctor(void (^log)(NSString *line),
                                  dt_rootless_r9_ctor_inputs_t *out);
void dt_rootless_leaf_cleanup(void);
#endif

#ifdef __cplusplus
}
#endif
