#import "DTKernelPath.h"

static NSString *DTFindKernelUnderPreboot(void)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *prebootRoot = @"/private/preboot";
    NSError *err = nil;
    NSArray *entries = [fm contentsOfDirectoryAtPath:prebootRoot error:&err];
    if (!entries) return nil;

    for (NSString *entry in entries) {
        if ([entry hasPrefix:@"."]) continue;
        NSString *candidate = [[prebootRoot stringByAppendingPathComponent:entry]
            stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"];
        if ([fm fileExistsAtPath:candidate]) {
            return candidate;
        }
    }
    return nil;
}

NSString *DTAccessibleKernelPath(void)
{
    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *prebootKernel = DTFindKernelUnderPreboot();
    if (prebootKernel) {
        return prebootKernel;
    }

    NSString *live = @"/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    if ([fm fileExistsAtPath:live]) {
        return live;
    }

    NSString *bundled = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"];
    if ([fm fileExistsAtPath:bundled]) {
        return bundled;
    }

    return nil;
}
