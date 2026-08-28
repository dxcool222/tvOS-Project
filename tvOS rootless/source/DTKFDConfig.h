#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DTKFDPuafMethod) {
    DTKFDPuafPhyspuppet = 0,
    DTKFDPuafSmith = 1,
    DTKFDPuafLanda = 2,
};

typedef NS_ENUM(NSInteger, DTKFDKreadMethod) {
    DTKFDKreadKqueueWorkloopCtl = 0,
    DTKFDKreadSemOpen = 1,
};

typedef NS_ENUM(NSInteger, DTKFDKwriteMethod) {
    DTKFDKwriteDup = 0,
    DTKFDKwriteSemOpen = 1,
};

typedef NS_ENUM(NSInteger, DTKernelExploitMethod) {
    DTKernelExploitDarkSword = 0,
    DTKernelExploitKFD = 1,
};

/// User-selectable kfd options (same surface as misaka/J on tvOS).
@interface DTKFDConfig : NSObject <NSCopying, NSSecureCoding>

/// Default kernel exploit: DarkSword. KFD remains selectable fallback.
@property (nonatomic) DTKernelExploitMethod kernelExploit;

/// PUAF page count — pick from +puafPageOptions (same as misaka/J). 0 = auto by RAM/CPU.
@property (nonatomic) int puafPages;

/// 16 … 131072 — matches J Memory.puaf_pages_options
+ (NSArray<NSNumber *> *)puafPageOptions;
@property (nonatomic) DTKFDPuafMethod puafMethod;
@property (nonatomic) DTKFDKreadMethod kreadMethod;
@property (nonatomic) DTKFDKwriteMethod kwriteMethod;

+ (instancetype)sharedConfig;
+ (instancetype)misakaDefaults;
- (void)save;
- (NSString *)puafFlavorName;
- (NSString *)summaryString;

@end

NS_ASSUME_NONNULL_END
