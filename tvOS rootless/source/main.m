#import <UIKit/UIKit.h>
#import "DTKFDRunner.h"
#import "DTKFDConfig.h"
#import "DTSettingsViewController.h"
#import "DTLogCapture.h"
#import "DTRunLogger.h"
#import "DTBootstrap.h"
#import "dt_respring.h"
#import "dt_build102739n.h"
#ifdef DT_ROOTLESS_R4
#import "dt_rootless_r6.h"
#import "dt_rootless_platform_device.h"
#import "dt_rootless_orch.h"
#endif
#import <sys/sysctl.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@interface RootVC : UIViewController
@end

static const NSUInteger kDTMaxStageLines = 40;

static UIColor *MisakaBlue(void)
{
    return [UIColor colorWithRed:0.08 green:0.14 blue:0.28 alpha:1];
}

static UIColor *PanelFill(void)
{
    return [UIColor colorWithWhite:1 alpha:0.06];
}

static NSString *DTShortStageLabel(NSString *stage)
{
    static NSDictionary<NSString *, NSString *> *map;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        map = @{
            @"starting": @"Starting",
            @"offsets baked": @"Offsets loaded",
            @"offsets plist": @"Offsets (plist)",
            @"offsets patchfind": @"Patchfinding offsets",
            @"kopen": @"Running kopen…",
            @"kopen OK": @"kopen OK",
            @"kopen failed": @"kopen failed",
            @"do_fun": @"Running do_fun…",
            @"do_fun OK": @"do_fun OK",
            @"do_fun failed": @"do_fun failed",
            @"kfd active": @"kfd active",
            @"closing kfd": @"Closing kfd…",
            @"kfd closed": @"kfd closed",
            @"exception": @"Exception",
            @"build21 baked offsets verify": @"Baked offsets (build 21)",
            @"build21 proc.task=0": @"proc.task=0",
            @"build21 proc.size=0x720": @"proc.size=0x720",
            @"build21 pmap.sw_asid=0x8E": @"pmap.sw_asid=0x8E",
            @"build21 vm_map.pmap=0x40": @"vm_map.pmap=0x40",
            @"pte kwrite disabled build21": @"PTE kwrite off",
            @"pte kwrite not ready build21": @"PTE not ready",
            @"pte kwrite ready build21": @"PTE ready",
            @"build48 bootstrap gate open": @"Bootstrap unlocked",
            @"build50 bootstrap gate open": @"Bootstrap unlocked",
            @"build50 G1 OK": @"G1 probe OK",
            @"build50 G2 OK": @"G2 extract OK",
            @"build50 G3 OK": @"G3 symlink audit OK",
            @"build50 G4 OK": @"G4 ldid smoke OK",
            @"build50 G5 OK": @"G5 sign+smoke OK",
            @"build102.5.2 KCALL_CALIBRATION_OK": @"kcall calibration OK",
            @"build102.5.2 KCALL_SAFE_PROBE_OK": @"kcall proc_pid OK",
            @"build102.5.2 KCALL_RETURN_CAPTURE_FAIL": @"kcall return capture fail",
            @"build102.5.2 KCALL_PROC_PID_ARG_FAIL": @"kcall proc_pid arg fail",
            @"build102.5 KCALL_SAFE_PROBE_OK": @"kcall proc_pid OK",
            @"build102.5 KCALL_CONSUME_APP_HANDLE_OK": @"kcall consume OK",
            @"build102.5 KCALL_CONSUME_HANDLE_ZERO": @"kcall consume h=0",
            @"build102.5 KCALL_UNAVAILABLE": @"kcall unavailable",
            @"build102.5 KCALL_SAFE_PROBE_FAIL": @"kcall probe fail",
            @"build102.4 G5 helper dash smoke PASS": @"G5 ext+dash OK",
            @"build102.4 HELPER_SMOKE_INVOKED": @"helper smoke invoked",
            @"build102.4 verdict=HELPER_EXT_FIXES_DASH": @"ext fixes dash",
            @"build102.4 verdict=HELPER_EXT_ISSUE_FAIL": @"ext issue fail",
            @"build102.4 verdict=HELPER_EXT_CONSUME_ZERO": @"ext consume zero",
            @"build102.4 verdict=NEED_5510E8_BP_HELPER_PID": @"need kernel BP",
            @"build102.4 verdict=HELPER_EXT_CONSUME_OK_DASH_FAIL": @"ext OK dash fail",
            @"build102.3.3 G5 helper dash smoke PASS": @"G5 dash smoke OK",
            @"build102.3.3 dash trust OK": @"dash trusted",
            @"build102.3.3 helper ping OK": @"helper ping OK",
            @"build102.3.3 HELPER_SMOKE_INVOKED": @"helper smoke invoked",
            @"build102.3.3 verdict=HELPER_ARCH_WORKS": @"helper arch works",
            @"build102.3.3 verdict=HELPER_ARCH_WORKS_APP_CONTEXT_BAD": @"helper works app bad",
            @"build102.3.3 verdict=HELPER_PREFLIGHT_BUG": @"helper preflight bug",
            @"build102.3.3 verdict=HELPER_DASH_EXEC_FAIL": @"helper dash exec fail",
            @"build102.3.3 verdict=TRUSTCACHE_REPLACEMENT_BUG": @"trustcache replacement bug",
            @"build102.2 G5 helper launch fixed": @"G5 helper launch fixed",
            @"build102.2 G5 helper launch not fixed": @"G5 helper launch not fixed",
            @"build102.2 classifier complete": @"classifier complete",
            @"build102.2 helper ping OK (jb persona)": @"jb persona ping OK",
            @"build102.1 G5 helper proof PASS": @"G5 helper proof OK",
            @"build102.1 G5 helper proof FAIL": @"G5 helper proof fail",
            @"build102.1 helper ping OK": @"helper ping OK",
            @"build102.1 dash trust OK": @"dash trusted",
            @"build102.1 dash trust FAIL": @"dash trust fail",
            @"build50 ldid T0 OK": @"ldid T0 OK",
            @"build50 smoke bash --version OK": @"bash smoke OK",
            @"build50 smoke Killed:9": @"bash Killed:9",
            @"build50 smoke probe ldbundle OK": @"probe ldbundle OK",
            @"build50 smoke probe dash OK": @"probe dash OK",
            @"build50 smoke probe bash OK": @"probe bash OK",
            @"build50 G52 summary": @"G52 diag summary",
            @"build50 G52 cdhash dash postsign tcached=0": @"dash hash not in TC",
            @"build50 G52 cdhash dash postsign tcached=1": @"dash hash in TC",
            @"build50 rollback OK": @"Rollback OK",
            @"build50 symlink audit critical_remaining=0": @"Symlinks OK",
            @"build50 G3 fail no remount gate": @"G3: run Exploit first",
            @"build50 G3 fail need root": @"G3: need root",
            @"build50 G3 fail EROFS": @"G3: / read-only",
            @"build51 probe exploit_init enter": @"Probe: init enter",
            @"build51 probe exploit_init OK": @"Probe: init OK",
            @"build51 probe exploit_deinit OK": @"Probe: deinit OK",
            @"build51 probe build26 enter": @"Probe: build26 enter",
            @"build51 probe build26 OK": @"Probe: build26 OK",
            @"build51 probe physrw_init OK": @"Probe: physrw OK",
            @"build26 tc upload begin": @"build26 uploading…",
            @"build50 G2 bash OK": @"bash on disk",
            @"build50 G1 fail no remount gate": @"G1: run Exploit first",
            @"build50 G2 fail no remount gate": @"G2: run Exploit first",
            @"build50 rollback fail no remount gate": @"Rollback: run Exploit first",
            @"build50 G1 fail need root": @"G1: need root",
            @"build50 G2 fail need root": @"G2: need root",
            @"build50 G1 fail EROFS": @"G1: / read-only",
            @"build50 G2 fail EROFS": @"G2: / read-only",
            @"build50 rollback fail need root": @"Rollback: need root",
            @"build50 rollback fail EROFS": @"Rollback: / read-only",
            @"build50 probe OK": @"Probe files written",
        };
    });
    return map[stage] ?: stage;
}

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[RootVC alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}

@end

@implementation RootVC {
    UIView *_panel;
    UILabel *_statusLabel;
    UILabel *_detailLabel;
    UITextView *_stageView;
    DTKFDRunner *_runner;
    UIButton *_exploitBtn;
    UIButton *_bootstrapG1Btn;
    UIButton *_bootstrapRollbackBtn;
    UIButton *_bootstrapG2Btn;
    UIButton *_bootstrapG3Btn;
    UIButton *_bootstrapG4Btn;
    UIButton *_bootstrapG5Btn;
    UIButton *_settingsBtn;
    UIActivityIndicatorView *_spinner;
    BOOL _running;
    BOOL _bootstrapRunning;
    NSMutableArray<NSString *> *_stageLines;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.view.backgroundColor = MisakaBlue();
    _runner = [DTKFDRunner new];
    _stageLines = [NSMutableArray array];

    __weak typeof(self) weakSelf = self;
    [[DTRunLogger shared] setUiStageHandler:^(NSString *stage) {
        [weakSelf onStage:stage];
    }];
    [[DTRunLogger shared] open];

    UILabel *title = [[UILabel alloc] init];
    title.text = @"dopamin tvOS kfd";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont italicSystemFontOfSize:34];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    _panel = [[UIView alloc] init];
    _panel.backgroundColor = PanelFill();
    _panel.layer.cornerRadius = 10;
    _panel.clipsToBounds = YES;
    _panel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_panel];

    _statusLabel = [[UILabel alloc] init];
    _statusLabel.textColor = UIColor.whiteColor;
    _statusLabel.font = [UIFont systemFontOfSize:32 weight:UIFontWeightSemibold];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.numberOfLines = 2;
    _statusLabel.adjustsFontSizeToFitWidth = YES;
    _statusLabel.minimumScaleFactor = 0.7;
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [_panel addSubview:_statusLabel];

    _detailLabel = [[UILabel alloc] init];
    _detailLabel.textColor = [UIColor colorWithWhite:1 alpha:0.62];
    _detailLabel.font = [UIFont systemFontOfSize:20 weight:UIFontWeightRegular];
    _detailLabel.textAlignment = NSTextAlignmentCenter;
    _detailLabel.numberOfLines = 3;
    _detailLabel.adjustsFontSizeToFitWidth = YES;
    _detailLabel.minimumScaleFactor = 0.75;
    _detailLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [_panel addSubview:_detailLabel];

    _stageView = [[UITextView alloc] init];
    _stageView.backgroundColor = UIColor.clearColor;
    _stageView.textColor = [UIColor colorWithWhite:1 alpha:0.88];
    _stageView.font = [UIFont monospacedSystemFontOfSize:22 weight:UIFontWeightRegular];
    _stageView.selectable = NO;
    _stageView.userInteractionEnabled = NO;
    _stageView.scrollEnabled = YES;
    _stageView.textContainerInset = UIEdgeInsetsMake(8, 4, 8, 4);
    _stageView.translatesAutoresizingMaskIntoConstraints = NO;
    [_panel addSubview:_stageView];

    _exploitBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_exploitBtn setTitle:@"Exploit" forState:UIControlStateNormal];
    _exploitBtn.titleLabel.font = [UIFont systemFontOfSize:26 weight:UIFontWeightMedium];
    _exploitBtn.backgroundColor = [UIColor colorWithWhite:1 alpha:0.12];
    _exploitBtn.layer.cornerRadius = 10;
    _exploitBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [_exploitBtn addTarget:self action:@selector(exploitTapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_exploitBtn];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.hidesWhenStopped = YES;
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    [_exploitBtn addSubview:_spinner];

    UIButton *settings = [UIButton buttonWithType:UIButtonTypeSystem];
    _settingsBtn = settings;
    [settings setTitle:@"Settings" forState:UIControlStateNormal];
    settings.titleLabel.font = [UIFont systemFontOfSize:26 weight:UIFontWeightMedium];
    settings.backgroundColor = [UIColor colorWithRed:0.2 green:0.45 blue:0.85 alpha:1];
    settings.layer.cornerRadius = 10;
    settings.translatesAutoresizingMaskIntoConstraints = NO;
    [settings addTarget:self action:@selector(settingsTapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:settings];

#ifndef DT_BUILD102739M_VARIANT
    UIButton *respring = [UIButton buttonWithType:UIButtonTypeSystem];
    [respring setTitle:@"Respring" forState:UIControlStateNormal];
    respring.titleLabel.font = [UIFont systemFontOfSize:26 weight:UIFontWeightMedium];
    respring.backgroundColor = [UIColor colorWithRed:0.12 green:0.22 blue:0.42 alpha:1];
    respring.layer.cornerRadius = 10;
    respring.translatesAutoresizingMaskIntoConstraints = NO;
    [respring addTarget:self action:@selector(respringTapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:respring];

    _bootstrapG1Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_bootstrapG1Btn setTitle:@"Bootstrap G1" forState:UIControlStateNormal];
    _bootstrapG1Btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapG1Btn.backgroundColor = [UIColor colorWithRed:0.15 green:0.55 blue:0.32 alpha:1];
    _bootstrapG1Btn.layer.cornerRadius = 10;
    _bootstrapG1Btn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapG1Btn.enabled = NO;
    _bootstrapG1Btn.alpha = 0.45;
    [_bootstrapG1Btn addTarget:self action:@selector(bootstrapG1Tapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapG1Btn];

    _bootstrapRollbackBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_bootstrapRollbackBtn setTitle:@"Rollback" forState:UIControlStateNormal];
    _bootstrapRollbackBtn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapRollbackBtn.backgroundColor = [UIColor colorWithRed:0.62 green:0.18 blue:0.18 alpha:1];
    _bootstrapRollbackBtn.layer.cornerRadius = 10;
    _bootstrapRollbackBtn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapRollbackBtn.enabled = NO;
    _bootstrapRollbackBtn.alpha = 0.45;
    [_bootstrapRollbackBtn addTarget:self action:@selector(bootstrapRollbackTapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapRollbackBtn];

    _bootstrapG2Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_bootstrapG2Btn setTitle:@"Bootstrap G2" forState:UIControlStateNormal];
    _bootstrapG2Btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapG2Btn.backgroundColor = [UIColor colorWithRed:0.12 green:0.42 blue:0.55 alpha:1];
    _bootstrapG2Btn.layer.cornerRadius = 10;
    _bootstrapG2Btn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapG2Btn.enabled = NO;
    _bootstrapG2Btn.alpha = 0.45;
    [_bootstrapG2Btn addTarget:self action:@selector(bootstrapG2Tapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapG2Btn];

    _bootstrapG3Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_bootstrapG3Btn setTitle:@"Bootstrap G3" forState:UIControlStateNormal];
    _bootstrapG3Btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapG3Btn.backgroundColor = [UIColor colorWithRed:0.38 green:0.28 blue:0.55 alpha:1];
    _bootstrapG3Btn.layer.cornerRadius = 10;
    _bootstrapG3Btn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapG3Btn.enabled = NO;
    _bootstrapG3Btn.alpha = 0.45;
    [_bootstrapG3Btn addTarget:self action:@selector(bootstrapG3Tapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapG3Btn];

    _bootstrapG4Btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [_bootstrapG4Btn setTitle:@"Bootstrap G4" forState:UIControlStateNormal];
    _bootstrapG4Btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapG4Btn.backgroundColor = [UIColor colorWithRed:0.55 green:0.35 blue:0.18 alpha:1];
    _bootstrapG4Btn.layer.cornerRadius = 10;
    _bootstrapG4Btn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapG4Btn.enabled = NO;
    _bootstrapG4Btn.alpha = 0.45;
    [_bootstrapG4Btn addTarget:self action:@selector(bootstrapG4Tapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapG4Btn];
#endif

    _bootstrapG5Btn = [UIButton buttonWithType:UIButtonTypeSystem];
#ifdef DT_BUILD102739M_VARIANT
    [_bootstrapG5Btn setTitle:@"Run Bring-Up" forState:UIControlStateNormal];
#else
    [_bootstrapG5Btn setTitle:@"Bootstrap G5" forState:UIControlStateNormal];
#endif
    _bootstrapG5Btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    _bootstrapG5Btn.backgroundColor = [UIColor colorWithRed:0.18 green:0.52 blue:0.38 alpha:1];
    _bootstrapG5Btn.layer.cornerRadius = 10;
    _bootstrapG5Btn.translatesAutoresizingMaskIntoConstraints = NO;
    _bootstrapG5Btn.enabled = NO;
    _bootstrapG5Btn.alpha = 0.45;
    [_bootstrapG5Btn addTarget:self action:@selector(bootstrapG5Tapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:_bootstrapG5Btn];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:g.topAnchor constant:28],
        [title.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [_panel.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:24],
        [_panel.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_panel.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_panel.heightAnchor constraintEqualToAnchor:g.heightAnchor multiplier:0.52],
        [_statusLabel.topAnchor constraintEqualToAnchor:_panel.topAnchor constant:20],
        [_statusLabel.leadingAnchor constraintEqualToAnchor:_panel.leadingAnchor constant:20],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:_panel.trailingAnchor constant:-20],
        [_detailLabel.topAnchor constraintEqualToAnchor:_statusLabel.bottomAnchor constant:10],
        [_detailLabel.leadingAnchor constraintEqualToAnchor:_panel.leadingAnchor constant:20],
        [_detailLabel.trailingAnchor constraintEqualToAnchor:_panel.trailingAnchor constant:-20],
        [_stageView.topAnchor constraintEqualToAnchor:_detailLabel.bottomAnchor constant:16],
        [_stageView.leadingAnchor constraintEqualToAnchor:_panel.leadingAnchor constant:16],
        [_stageView.trailingAnchor constraintEqualToAnchor:_panel.trailingAnchor constant:-16],
        [_stageView.bottomAnchor constraintEqualToAnchor:_panel.bottomAnchor constant:-16],
        [_exploitBtn.topAnchor constraintEqualToAnchor:_panel.bottomAnchor constant:28],
        [_exploitBtn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_exploitBtn.heightAnchor constraintEqualToConstant:56],
        [_exploitBtn.widthAnchor constraintEqualToAnchor:settings.widthAnchor],
        [settings.topAnchor constraintEqualToAnchor:_exploitBtn.topAnchor],
        [settings.leadingAnchor constraintEqualToAnchor:_exploitBtn.trailingAnchor constant:16],
        [settings.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [settings.heightAnchor constraintEqualToAnchor:_exploitBtn.heightAnchor],
        [_spinner.centerYAnchor constraintEqualToAnchor:_exploitBtn.centerYAnchor],
        [_spinner.trailingAnchor constraintEqualToAnchor:_exploitBtn.trailingAnchor constant:-16],
#ifdef DT_BUILD102739M_VARIANT
        [_bootstrapG5Btn.topAnchor constraintEqualToAnchor:_exploitBtn.bottomAnchor constant:16],
        [_bootstrapG5Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG5Btn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapG5Btn.heightAnchor constraintEqualToConstant:56],
        [_bootstrapG5Btn.bottomAnchor constraintLessThanOrEqualToAnchor:g.bottomAnchor constant:-24],
#else
        [respring.topAnchor constraintEqualToAnchor:_exploitBtn.bottomAnchor constant:16],
        [respring.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [respring.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [respring.heightAnchor constraintEqualToConstant:56],
        [_bootstrapG1Btn.topAnchor constraintEqualToAnchor:respring.bottomAnchor constant:16],
        [_bootstrapG1Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG1Btn.heightAnchor constraintEqualToConstant:48],
        [_bootstrapRollbackBtn.topAnchor constraintEqualToAnchor:_bootstrapG1Btn.topAnchor],
        [_bootstrapRollbackBtn.leadingAnchor constraintEqualToAnchor:_bootstrapG1Btn.trailingAnchor constant:12],
        [_bootstrapRollbackBtn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapRollbackBtn.heightAnchor constraintEqualToAnchor:_bootstrapG1Btn.heightAnchor],
        [_bootstrapRollbackBtn.widthAnchor constraintEqualToAnchor:_bootstrapG1Btn.widthAnchor],
        [_bootstrapG2Btn.topAnchor constraintEqualToAnchor:_bootstrapG1Btn.bottomAnchor constant:12],
        [_bootstrapG2Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG2Btn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapG2Btn.heightAnchor constraintEqualToConstant:48],
        [_bootstrapG3Btn.topAnchor constraintEqualToAnchor:_bootstrapG2Btn.bottomAnchor constant:12],
        [_bootstrapG3Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG3Btn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapG3Btn.heightAnchor constraintEqualToConstant:48],
        [_bootstrapG4Btn.topAnchor constraintEqualToAnchor:_bootstrapG3Btn.bottomAnchor constant:12],
        [_bootstrapG4Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG4Btn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapG4Btn.heightAnchor constraintEqualToConstant:48],
        [_bootstrapG5Btn.topAnchor constraintEqualToAnchor:_bootstrapG4Btn.bottomAnchor constant:12],
        [_bootstrapG5Btn.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_bootstrapG5Btn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
        [_bootstrapG5Btn.heightAnchor constraintEqualToConstant:48],
        [_bootstrapG5Btn.bottomAnchor constraintLessThanOrEqualToAnchor:g.bottomAnchor constant:-24],
#endif
    ]];

    [self showIdleState];
    [self refreshBootstrapButtons];
}

- (void)refreshBootstrapButtons
{
    BOOL bootstrapOn = [DTBootstrap remountWritable] && !_running && !_bootstrapRunning;
    BOOL rollbackOn = [DTBootstrap remountWritable] && !_running;
#ifdef DT_ROOTLESS_R4
    /* R10: only G5 Bring-Up is a product UI entry. G1–G4/rollback stay visible but disabled. */
    BOOL bringUpOn = !_running && !_bootstrapRunning;
    _bootstrapG1Btn.enabled = NO;
    _bootstrapRollbackBtn.enabled = NO;
    _bootstrapG2Btn.enabled = NO;
    _bootstrapG3Btn.enabled = NO;
    _bootstrapG4Btn.enabled = NO;
    _bootstrapG5Btn.enabled = bringUpOn;
    _bootstrapG1Btn.alpha = 0.45;
    _bootstrapRollbackBtn.alpha = 0.45;
    _bootstrapG2Btn.alpha = 0.45;
    _bootstrapG3Btn.alpha = 0.45;
    _bootstrapG4Btn.alpha = 0.45;
    _bootstrapG5Btn.alpha = bringUpOn ? 1.0 : 0.45;
#else
    BOOL bringUpOn = bootstrapOn;
    _bootstrapG1Btn.enabled = bootstrapOn;
    _bootstrapRollbackBtn.enabled = rollbackOn;
    _bootstrapG2Btn.enabled = bootstrapOn;
    _bootstrapG3Btn.enabled = bootstrapOn;
    _bootstrapG4Btn.enabled = bootstrapOn;
    _bootstrapG5Btn.enabled = bringUpOn;
    _bootstrapG1Btn.alpha = bootstrapOn ? 1.0 : 0.45;
    _bootstrapRollbackBtn.alpha = rollbackOn ? 1.0 : 0.45;
    _bootstrapG2Btn.alpha = bootstrapOn ? 1.0 : 0.45;
    _bootstrapG3Btn.alpha = bootstrapOn ? 1.0 : 0.45;
    _bootstrapG4Btn.alpha = bootstrapOn ? 1.0 : 0.45;
    _bootstrapG5Btn.alpha = bringUpOn ? 1.0 : 0.45;
#endif
#ifdef DT_ROOTLESS_R4
    [_bootstrapG5Btn setTitle:@"Run Bring-Up" forState:UIControlStateNormal];
#else
    if ([DTBootstrap remountWritable]) {
#ifdef DT_BUILD102739M_VARIANT
        [_bootstrapG5Btn setTitle:@"Run Bring-Up" forState:UIControlStateNormal];
#else
        [_bootstrapG1Btn setTitle:@"G1 probe" forState:UIControlStateNormal];
        [_bootstrapRollbackBtn setTitle:@"Rollback /var/jb" forState:UIControlStateNormal];
        [_bootstrapG2Btn setTitle:@"G2 extract" forState:UIControlStateNormal];
        [_bootstrapG3Btn setTitle:@"G3 symlinks" forState:UIControlStateNormal];
        [_bootstrapG4Btn setTitle:@"G4 ldid" forState:UIControlStateNormal];
        [_bootstrapG5Btn setTitle:@"697 B4-FILE diag" forState:UIControlStateNormal];
#endif
    }
#endif
}

- (NSString *)deviceSummary
{
    char machine[64] = {0};
    char osversion[64] = {0};
    size_t len = sizeof(machine);
    sysctlbyname("hw.machine", machine, &len, NULL, 0);
    len = sizeof(osversion);
    sysctlbyname("kern.osversion", osversion, &len, NULL, 0);
    return [NSString stringWithFormat:@"%s · build %s", machine, osversion];
}

- (void)showIdleState
{
    _statusLabel.text = @"Ready";
    _detailLabel.text = [NSString stringWithFormat:@"%@\nConsole: filter dopamin-tvOS-kfd · search STAGE",
        [self deviceSummary]];
    [_stageLines removeAllObjects];
    _stageView.text = @"";
}

- (void)refreshStageView
{
    NSArray<NSString *> *snapshot = [_stageLines copy];
    NSMutableString *text = [NSMutableString string];
    for (NSString *line in snapshot) {
        [text appendFormat:@"› %@\n", line];
    }
    _stageView.text = text;
    if (text.length) {
        NSRange bottom = NSMakeRange(text.length - 1, 1);
        [_stageView scrollRangeToVisible:bottom];
    }
}

- (void)setStatus:(NSString *)status detail:(NSString *)detail
{
    if (status.length)
        _statusLabel.text = status;
    if (detail.length)
        _detailLabel.text = detail;
}

- (void)onStage:(NSString *)stage
{
    if (!stage.length) return;
    NSString *label = DTShortStageLabel(stage);
    _statusLabel.text = label;
    NSString *row = stage;
    if (_stageLines.count && [_stageLines.lastObject isEqualToString:row])
        return;
    [_stageLines addObject:row];
    while (_stageLines.count > kDTMaxStageLines) {
        [_stageLines removeObjectAtIndex:0];
    }
    [self refreshStageView];
}

- (void)setExploiting:(BOOL)on
{
    _running = on;
    _exploitBtn.enabled = !on;
    _settingsBtn.enabled = !on;
    if (on) {
        [_exploitBtn setTitle:@"Exploiting…" forState:UIControlStateNormal];
        [_spinner startAnimating];
    } else {
        [_exploitBtn setTitle:[DTKFDRunner isActive] ? @"Close kfd" : @"Exploit" forState:UIControlStateNormal];
        [_spinner stopAnimating];
    }
    [self refreshBootstrapButtons];
}

- (void)refreshExploitButton
{
    if (_running) return;
    [_exploitBtn setTitle:[DTKFDRunner isActive] ? @"Close kfd" : @"Exploit" forState:UIControlStateNormal];
}

- (void)settingsTapped
{
    if (_running) return;
    DTSettingsViewController *vc = [DTSettingsViewController new];
    vc.onClose = ^(DTKFDConfig *config) {
        (void)config;
    };
#ifdef DT_BUILD102739M_VARIANT
    __weak typeof(self) weakSelf = self;
    vc.onRespring = ^{
        [weakSelf respringTapped];
    };
    vc.onRemoveLegacyBootstrap = ^{
        [weakSelf dismissViewControllerAnimated:YES completion:^{
            [weakSelf bootstrapRollbackTapped];
        }];
    };
#endif
    vc.modalPresentationStyle = UIModalPresentationOverFullScreen;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)respringTapped
{
    [self setStatus:@"Respringing…" detail:nil];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        dt_respring();
    });
}

- (void)bootstrapG1Tapped
{
#ifdef DT_ROOTLESS_R4
    return;
#endif
    if (_running || _bootstrapRunning || ![DTBootstrap remountWritable]) return;

    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Bootstrap G1…" detail:@"Probe only — optional marker files"];

    __weak typeof(self) weakSelf = self;
    [DTBootstrap runG1ProbeWithCompletion:^(BOOL ok, NSString *detail) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        if (ok) {
            [self setStatus:@"G1 probe OK" detail:detail];
            [[DTRunLogger shared] log:@"run finished OK: build50 G1 probe"];
        } else {
            [self setStatus:@"G1 failed" detail:detail];
            [[DTRunLogger shared] log:[NSString stringWithFormat:@"run finished FAILED: build50 G1 %@", detail]];
        }
    }];
}

- (void)bootstrapRollbackTapped
{
#ifdef DT_ROOTLESS_R4
    return;
#endif
    if (_running || ![DTBootstrap remountWritable]) return;

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Rollback /var/jb?"
                                                                   message:@"Deletes the entire /var/jb tree (probes + bootstrap). Stock OS is not touched."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"Delete /var/jb" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [weakSelf performRollback];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)performRollback
{
    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Rolling back…" detail:@"Removing /var/jb only"];

    __weak typeof(self) weakSelf = self;
    [DTBootstrap runRollbackWithCompletion:^(BOOL ok, NSString *detail) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        if (ok) {
            [self setStatus:@"Rollback OK" detail:detail];
            [[DTRunLogger shared] log:@"run finished OK: build50 rollback"];
        } else {
            [self setStatus:@"Rollback failed" detail:detail];
            [[DTRunLogger shared] log:[NSString stringWithFormat:@"run finished FAILED: build50 rollback %@", detail]];
        }
    }];
}

- (void)bootstrapG2Tapped
{
#ifdef DT_ROOTLESS_R4
    return;
#endif
    if (_running || _bootstrapRunning || ![DTBootstrap remountWritable]) return;

    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Bootstrap G2…" detail:@"bash + dash + dylibs → /var/jb (no exec)"];

    __weak typeof(self) weakSelf = self;
    [DTBootstrap runG2ExtractWithCompletion:^(BOOL ok, NSString *detail) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        if (ok) {
            [self setStatus:@"G2 extract OK" detail:detail];
            [[DTRunLogger shared] log:@"run finished OK: build50 G2 extract"];
        } else {
            [self setStatus:@"G2 failed" detail:detail];
            [[DTRunLogger shared] log:[NSString stringWithFormat:@"run finished FAILED: build50 G2 %@", detail]];
        }
    }];
}

- (void)bootstrapG3Tapped
{
#ifdef DT_ROOTLESS_R4
    return;
#endif
    if (_running || _bootstrapRunning || ![DTBootstrap remountWritable]) return;

    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Bootstrap G3…" detail:@"Audit symlinks under /var/jb (fix absolute → /var/jb+path)"];

    __weak typeof(self) weakSelf = self;
    [DTBootstrap runG3SymlinkAuditWithCompletion:^(BOOL ok, NSString *detail) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        if (ok) {
            [self setStatus:@"G3 symlink audit OK" detail:detail];
            [[DTRunLogger shared] log:@"run finished OK: build50 G3 symlink audit"];
        } else {
            [self setStatus:@"G3 failed" detail:detail];
            [[DTRunLogger shared] log:[NSString stringWithFormat:@"run finished FAILED: build50 G3 %@", detail]];
        }
    }];
}

- (void)bootstrapG4Tapped
{
#ifdef DT_ROOTLESS_R4
    return;
#endif
    if (_running || _bootstrapRunning || ![DTBootstrap remountWritable]) return;

    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Bootstrap G4…" detail:@"Smoke bundled Tools/ldid (ldid -h)"];

    __weak typeof(self) weakSelf = self;
    [DTBootstrap runG4LdidSmokeWithCompletion:^(BOOL ok, NSString *detail) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        if (ok) {
            [self setStatus:@"G4 ldid smoke OK" detail:detail];
            [[DTRunLogger shared] log:@"run finished OK: build50 G4 ldid smoke"];
        } else {
            [self setStatus:@"G4 failed" detail:detail];
            [[DTRunLogger shared] log:[NSString stringWithFormat:@"run finished FAILED: build50 G4 %@", detail]];
        }
    }];
}

- (void)bootstrapG5Tapped
{
    if (_running || _bootstrapRunning) return;
#ifdef DT_ROOTLESS_R4
    [[DTRunLogger shared] beginExploitRun];
    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
    [self setStatus:@"Bring-Up running…" detail:@"shared orch REAL_DEVICE"];
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        dt_rootless_orch_result_t out = {0};
        int rc = dt_rootless_device_bringup(&out);
        NSString *v = out.result[0] ? [NSString stringWithUTF8String:out.result] : @"INCOMPLETE";
        BOOL ok = (rc == 0 && out.committed);
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self->_bootstrapRunning = NO;
            [self refreshBootstrapButtons];
            if (ok) {
                [self setStatus:@"Bring-Up complete" detail:v];
                [[DTRunLogger shared] log:[NSString stringWithFormat:
                    @"run finished OK: %@", v]];
            } else {
                [self setStatus:@"Bring-Up failed" detail:v];
                [[DTRunLogger shared] log:[NSString stringWithFormat:
                    @"run finished: %@", v]];
            }
        });
    });
    return;
#else /* !DT_ROOTLESS_R4 — preserve legacy Bring-Up entry */
    if (![DTBootstrap remountWritable]) return;

    if (![DTKFDRunner isActive]) {
        [self setStatus:@"653 telemetry blocked" detail:@"Run Exploit first (kfd must be active)"];
        return;
    }

#ifdef DT_BUILD102739N_VARIANT
    [[DTRunLogger shared] beginExploitRun];
    NSString *classificationVerdict = nil;
    DTBuild102739NDispatch nDispatch =
        dt_build102739n_classify_before_chain(nil, &classificationVerdict);
    if (nDispatch == DTBuild102739NDispatchStop) {
        NSString *detail = classificationVerdict ?: @"N state classifier stopped";
        [self setStatus:@"Bring-Up paused" detail:detail];
        [[DTRunLogger shared] log:[NSString stringWithFormat:
            @"run finished: BUILD102739N classifier %@", detail]];
        return;
    }
#endif

    _bootstrapRunning = YES;
    [self refreshBootstrapButtons];
#ifdef DT_BUILD102739M_VARIANT
#ifdef DT_BUILD102739N_VARIANT
    [self setStatus:@"Bring-Up running…" detail:
        dt_build102739n_current_dispatch() == DTBuild102739NDispatchRunA
            ? @"J/K/L, M fresh proof, then N stage"
            : @"J/K/L then N reactivation"];
#else
    [self setStatus:@"Bring-Up running…" detail:@"J/K/L gates then M external helper proof"];
#endif
#else
    [self setStatus:@"699 platform hook…" detail:@"Phase A identity + Phase B launchd (BUILD102699)"];
#endif
    [[DTRunLogger shared] log:@"KCALL699_UI_TAP"];
    [[DTRunLogger shared] logStage:@"KCALL699_UI_TAP"];
#ifndef DT_BUILD102739N_VARIANT
    [[DTRunLogger shared] beginExploitRun];
#endif

    __weak typeof(self) weakSelf = self;
    [_runner run699PlatformHookClosureWithConfig:[DTKFDConfig misakaDefaults] log:nil
                                      completion:^(BOOL ok, NSString *summary) {
        __strong typeof(weakSelf) self = weakSelf;
        self->_bootstrapRunning = NO;
        [self refreshBootstrapButtons];
        NSString *v = summary ?: @"BUILD102699_DIAGNOSTIC_FAIL";
        if (ok) {
#ifdef DT_BUILD102739M_VARIANT
#ifdef DT_BUILD102739N_VARIANT
            if ([v containsString:@"PERSISTENT_CONTROL_FIXTURE_STAGE_PASS_AWAITING_REBOOT"])
                [self setStatus:@"Stage complete" detail:@"Normal reboot required, then run again"];
            else
                [self setStatus:@"Bring-Up complete" detail:v];
#else
            [self setStatus:@"Bring-Up complete" detail:v];
#endif
#else
            [self setStatus:@"699 platform hook complete" detail:v];
#endif
            [[DTRunLogger shared] log:[NSString stringWithFormat:
                @"run finished OK: build699 platform hook %@", v]];
        } else {
#ifdef DT_BUILD102739M_VARIANT
            [self setStatus:@"Bring-Up failed" detail:v];
#else
            [self setStatus:@"699 platform hook failed" detail:v];
#endif
            [[DTRunLogger shared] log:[NSString stringWithFormat:
                @"run finished: build699 platform hook %@", v]];
        }
    }];
#endif /* DT_ROOTLESS_R4 */
}

- (void)exploitTapped
{
    if (_running) return;

    if ([DTKFDRunner isActive]) {
        if (_bootstrapRunning) {
            [self setStatus:@"G5 kcall" detail:@"Wait for G5 kcall to finish before closing kfd"];
            [[DTRunLogger shared] log:@"[!] build102.3 blocked close kfd during G5 kcall"];
            [[DTRunLogger shared] logStage:@"build102.3 blocked close kfd G5 kcall running"];
            return;
        }
        [self setExploiting:YES];
        __weak typeof(self) weakSelf = self;
        [_runner closeWithLog:nil completion:^{
            [DTBootstrap setRemountWritable:NO];
            [weakSelf setExploiting:NO];
            [weakSelf refreshExploitButton];
            [weakSelf setStatus:@"Ready" detail:@"kfd closed"];
        }];
        return;
    }

    [DTBootstrap setRemountWritable:NO];

    [self setExploiting:YES];
    [_stageLines removeAllObjects];
    _stageView.text = @"";
    [self setStatus:@"Exploiting…" detail:[self deviceSummary]];

    [[DTRunLogger shared] beginExploitRun];
    [[DTLogCapture sharedCapture] startWithHandler:nil];

    __weak typeof(self) weakSelf = self;
    [_runner runWithConfig:[DTKFDConfig sharedConfig] log:nil completion:^(BOOL ok, NSString *summary) {
        [[DTLogCapture sharedCapture] stop];
        [weakSelf setExploiting:NO];
        [weakSelf refreshExploitButton];
        if (ok) {
            [weakSelf setStatus:@"kfd active" detail:summary];
            [weakSelf refreshBootstrapButtons];
        } else {
            [DTBootstrap setRemountWritable:NO];
            [weakSelf setStatus:@"Failed" detail:@"Console: search STAGE · dopamin-tvOS-kfd"];
        }
        [[DTRunLogger shared] log:ok ? [NSString stringWithFormat:@"run finished OK: %@", summary] : @"run finished FAILED"];
    }];
}

@end

int main(int argc, char *argv[])
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
