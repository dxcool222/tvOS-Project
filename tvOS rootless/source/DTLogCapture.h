#import <Foundation/Foundation.h>

/// Captures stdout/stderr (libkfd printf) like misaka/J LogStream.
@interface DTLogCapture : NSObject

+ (instancetype)sharedCapture;
- (void)startWithHandler:(void (^)(NSString *line))handler;
- (void)stop;

@end
