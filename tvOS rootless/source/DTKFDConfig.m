#import "DTKFDConfig.h"

static NSString *const kCfgKernelExploit = @"dt.kernelExploit";
static NSString *const kCfgPages = @"dt.kfd.puafPages";
static NSString *const kCfgPuaf = @"dt.kfd.puafMethod";
static NSString *const kCfgKread = @"dt.kfd.kreadMethod";
static NSString *const kCfgKwrite = @"dt.kfd.kwriteMethod";

@implementation DTKFDConfig

+ (NSArray<NSNumber *> *)puafPageOptions
{
    return @[@16, @32, @64, @128, @256, @512, @1024, @2048, @3072, @4096, @65536, @131072];
}

+ (BOOL)supportsSecureCoding { return YES; }

+ (instancetype)sharedConfig
{
    static DTKFDConfig *cfg;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cfg = [self loadSaved] ?: [self misakaDefaults];
    });
    return cfg;
}

+ (instancetype)misakaDefaults
{
    DTKFDConfig *c = [DTKFDConfig new];
    c.kernelExploit = DTKernelExploitDarkSword;
    c.puafPages = 2048;
    c.puafMethod = DTKFDPuafLanda;
    c.kreadMethod = DTKFDKreadSemOpen;
    c.kwriteMethod = DTKFDKwriteSemOpen;
    return c;
}

+ (instancetype)loadSaved
{
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    if ([d objectForKey:kCfgPages] == nil) return nil;
    DTKFDConfig *c = [DTKFDConfig new];
    if ([d objectForKey:kCfgKernelExploit] != nil)
        c.kernelExploit = (DTKernelExploitMethod)[d integerForKey:kCfgKernelExploit];
    else
        c.kernelExploit = DTKernelExploitDarkSword;
    c.puafPages = (int)[d integerForKey:kCfgPages];
    c.puafMethod = (DTKFDPuafMethod)[d integerForKey:kCfgPuaf];
    c.kreadMethod = (DTKFDKreadMethod)[d integerForKey:kCfgKread];
    c.kwriteMethod = (DTKFDKwriteMethod)[d integerForKey:kCfgKwrite];
    return c;
}

- (void)save
{
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    [d setInteger:self.kernelExploit forKey:kCfgKernelExploit];
    [d setInteger:self.puafPages forKey:kCfgPages];
    [d setInteger:self.puafMethod forKey:kCfgPuaf];
    [d setInteger:self.kreadMethod forKey:kCfgKread];
    [d setInteger:self.kwriteMethod forKey:kCfgKwrite];
    [d synchronize];
}

- (id)copyWithZone:(NSZone *)zone
{
    DTKFDConfig *c = [DTKFDConfig new];
    c.kernelExploit = self.kernelExploit;
    c.puafPages = self.puafPages;
    c.puafMethod = self.puafMethod;
    c.kreadMethod = self.kreadMethod;
    c.kwriteMethod = self.kwriteMethod;
    return c;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeInteger:self.kernelExploit forKey:kCfgKernelExploit];
    [coder encodeInt:self.puafPages forKey:kCfgPages];
    [coder encodeInteger:self.puafMethod forKey:kCfgPuaf];
    [coder encodeInteger:self.kreadMethod forKey:kCfgKread];
    [coder encodeInteger:self.kwriteMethod forKey:kCfgKwrite];
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super init];
    if (self) {
        _kernelExploit = [coder decodeIntegerForKey:kCfgKernelExploit];
        _puafPages = [coder decodeIntForKey:kCfgPages];
        _puafMethod = [coder decodeIntegerForKey:kCfgPuaf];
        _kreadMethod = [coder decodeIntegerForKey:kCfgKread];
        _kwriteMethod = [coder decodeIntegerForKey:kCfgKwrite];
    }
    return self;
}

- (NSString *)puafFlavorName
{
    switch (self.puafMethod) {
        case DTKFDPuafPhyspuppet: return @"physpuppet";
        case DTKFDPuafSmith: return @"smith";
        case DTKFDPuafLanda: return @"landa";
    }
    return @"landa";
}

- (NSString *)summaryString
{
    static NSArray *kread = @[@"kqueue_workloop_ctl", @"sem_open"];
    static NSArray *kwrite = @[@"dup", @"sem_open"];
    if (self.kernelExploit == DTKernelExploitDarkSword)
        return @"DarkSword";
    NSString *pages = self.puafPages > 0 ? @(self.puafPages).stringValue : @"auto";
    return [NSString stringWithFormat:@"KFD %@ pages=%@ kread=%@ kwrite=%@",
            self.puafFlavorName, pages,
            kread[self.kreadMethod], kwrite[self.kwriteMethod]];
}

@end
