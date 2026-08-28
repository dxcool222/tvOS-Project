#import <UIKit/UIKit.h>

@class DTKFDConfig;

@interface DTSettingsViewController : UIViewController
@property (nonatomic, copy) void (^onClose)(DTKFDConfig *config);
@property (nonatomic, copy) void (^onRespring)(void);
@property (nonatomic, copy) void (^onRemoveLegacyBootstrap)(void);
@end
