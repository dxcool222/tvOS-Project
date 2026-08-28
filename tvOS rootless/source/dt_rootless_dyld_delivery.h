#pragma once
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif
int dt_rootless_prepare_dyld_delivery(void (^log)(NSString *), NSString **errOut);
#ifdef __cplusplus
}
#endif
