#import <Foundation/Foundation.h>

@interface DTDeviceInfo : NSObject
+ (void)logBannerTo:(void (^)(NSString *line))log;
@end
