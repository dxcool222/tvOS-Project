#import "DTSettingsViewController.h"
#import "DTKFDConfig.h"

@implementation DTSettingsViewController {
    DTKFDConfig *_cfg;
    UIScrollView *_pageScroll;
    UIStackView *_stack;
    UIStackView *_kfdStack;
    NSArray<UIButton *> *_pageButtons;
    UISegmentedControl *_exploitControl;
    UISegmentedControl *_puafControl;
    UISegmentedControl *_kreadControl;
    UISegmentedControl *_kwriteControl;
}

static NSArray<NSNumber *> *PageChoices(void)
{
    return [DTKFDConfig puafPageOptions];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    _cfg = [[DTKFDConfig sharedConfig] copy];
    self.view.backgroundColor = [UIColor colorWithRed:0.08 green:0.14 blue:0.28 alpha:1];

    UILabel *title = [[UILabel alloc] init];
    title.text = @"Settings";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:36];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    UISegmentedControl *mode = [[UISegmentedControl alloc] initWithItems:@[@"DarkSword", @"KFD"]];
    mode.selectedSegmentIndex = _cfg.kernelExploit;
    mode.translatesAutoresizingMaskIntoConstraints = NO;
    [mode addTarget:self action:@selector(exploitModeChanged:) forControlEvents:UIControlEventValueChanged];
    _exploitControl = mode;
    [self.view addSubview:mode];

    UILabel *pagesLabel = [[UILabel alloc] init];
    pagesLabel.text = @"Pages (KFD only)";
    pagesLabel.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    pagesLabel.font = [UIFont systemFontOfSize:22];

    _pageScroll = [[UIScrollView alloc] init];
    _pageScroll.showsHorizontalScrollIndicator = NO;
    [_pageScroll.heightAnchor constraintEqualToConstant:56].active = YES;

    UIStackView *pageRow = [[UIStackView alloc] init];
    pageRow.axis = UILayoutConstraintAxisHorizontal;
    pageRow.spacing = 12;
    pageRow.translatesAutoresizingMaskIntoConstraints = NO;
    [_pageScroll addSubview:pageRow];

    NSMutableArray *btns = [NSMutableArray array];
    for (NSNumber *n in PageChoices()) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:n.stringValue forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont monospacedSystemFontOfSize:22 weight:UIFontWeightMedium];
        b.tag = n.intValue;
        [b addTarget:self action:@selector(pageTapped:) forControlEvents:UIControlEventPrimaryActionTriggered];
        [pageRow addArrangedSubview:b];
        [btns addObject:b];
    }
    _pageButtons = btns;
    [self refreshPageSelection];

    [NSLayoutConstraint activateConstraints:@[
        [pageRow.topAnchor constraintEqualToAnchor:_pageScroll.topAnchor],
        [pageRow.bottomAnchor constraintEqualToAnchor:_pageScroll.bottomAnchor],
        [pageRow.leadingAnchor constraintEqualToAnchor:_pageScroll.leadingAnchor],
        [pageRow.trailingAnchor constraintEqualToAnchor:_pageScroll.trailingAnchor],
        [pageRow.heightAnchor constraintEqualToAnchor:_pageScroll.heightAnchor],
    ]];

    _puafControl = [self rowControl:@[@"physpuppet", @"smith", @"landa"] selected:_cfg.puafMethod];
    _kreadControl = [self rowControl:@[@"kqueue_workloop_ctl", @"sem_open"] selected:_cfg.kreadMethod];
    _kwriteControl = [self rowControl:@[@"dup", @"sem_open"] selected:_cfg.kwriteMethod];

    _stack = [[UIStackView alloc] initWithArrangedSubviews:@[pagesLabel, _pageScroll, _puafControl, _kreadControl, _kwriteControl]];
    _stack.axis = UILayoutConstraintAxisVertical;
    _stack.spacing = 28;
    _stack.translatesAutoresizingMaskIntoConstraints = NO;
    _kfdStack = _stack;
    [self.view addSubview:_stack];
    [self refreshKfdSettingsVisibility];

#ifdef DT_BUILD102739M_VARIANT
    UILabel *diagnosticsLabel = [[UILabel alloc] init];
    diagnosticsLabel.text = @"Diagnostics";
    diagnosticsLabel.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    diagnosticsLabel.font = [UIFont systemFontOfSize:22];

    UIButton *respring = [UIButton buttonWithType:UIButtonTypeSystem];
    [respring setTitle:@"Respring" forState:UIControlStateNormal];
    respring.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    [respring addTarget:self action:@selector(respringTapped) forControlEvents:UIControlEventPrimaryActionTriggered];

    UIButton *removeLegacy = [UIButton buttonWithType:UIButtonTypeSystem];
    [removeLegacy setTitle:@"Remove Legacy /var/jb" forState:UIControlStateNormal];
    removeLegacy.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    [removeLegacy setTitleColor:[UIColor colorWithRed:0.92 green:0.35 blue:0.35 alpha:1]
                      forState:UIControlStateNormal];
    [removeLegacy addTarget:self action:@selector(removeLegacyTapped)
           forControlEvents:UIControlEventPrimaryActionTriggered];

    UIStackView *diagnostics = [[UIStackView alloc] initWithArrangedSubviews:
        @[diagnosticsLabel, respring, removeLegacy]];
    diagnostics.axis = UILayoutConstraintAxisVertical;
    diagnostics.alignment = UIStackViewAlignmentLeading;
    diagnostics.spacing = 14;
    diagnostics.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:diagnostics];
#endif

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setTitle:@"Close" forState:UIControlStateNormal];
    close.titleLabel.font = [UIFont systemFontOfSize:28];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close addTarget:self action:@selector(closeTapped) forControlEvents:UIControlEventPrimaryActionTriggered];
    [self.view addSubview:close];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:g.topAnchor constant:32],
        [title.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [mode.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:28],
        [mode.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [mode.widthAnchor constraintGreaterThanOrEqualToConstant:320],
        [_stack.topAnchor constraintEqualToAnchor:mode.bottomAnchor constant:28],
        [_stack.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [_stack.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-48],
#ifdef DT_BUILD102739M_VARIANT
        [diagnostics.topAnchor constraintEqualToAnchor:_stack.bottomAnchor constant:28],
        [diagnostics.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:48],
        [diagnostics.trailingAnchor constraintLessThanOrEqualToAnchor:g.trailingAnchor constant:-48],
#endif
        [close.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-32],
        [close.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
    ]];
}

#ifdef DT_BUILD102739M_VARIANT
- (void)respringTapped
{
    if (self.onRespring)
        self.onRespring();
}

- (void)removeLegacyTapped
{
    if (self.onRemoveLegacyBootstrap)
        self.onRemoveLegacyBootstrap();
}
#endif

- (UISegmentedControl *)rowControl:(NSArray<NSString *> *)items selected:(NSInteger)idx
{
    UISegmentedControl *c = [[UISegmentedControl alloc] initWithItems:items];
    c.selectedSegmentIndex = idx;
    c.translatesAutoresizingMaskIntoConstraints = NO;
    return c;
}

- (void)refreshPageSelection
{
    for (UIButton *b in _pageButtons) {
        BOOL sel = (b.tag == _cfg.puafPages);
        [b setTitleColor:sel ? UIColor.whiteColor : [UIColor colorWithWhite:0.45 alpha:1] forState:UIControlStateNormal];
    }
}

- (void)exploitModeChanged:(UISegmentedControl *)sender
{
    _cfg.kernelExploit = (DTKernelExploitMethod)sender.selectedSegmentIndex;
    [self refreshKfdSettingsVisibility];
}

- (void)refreshKfdSettingsVisibility
{
    BOOL kfd = (_cfg.kernelExploit == DTKernelExploitKFD);
    _kfdStack.hidden = !kfd;
}

- (void)pageTapped:(UIButton *)sender
{
    _cfg.puafPages = (int)sender.tag;
    [self refreshPageSelection];
}

- (void)closeTapped
{
    _cfg.kernelExploit = (DTKernelExploitMethod)_exploitControl.selectedSegmentIndex;
    _cfg.puafMethod = (DTKFDPuafMethod)_puafControl.selectedSegmentIndex;
    _cfg.kreadMethod = (DTKFDKreadMethod)_kreadControl.selectedSegmentIndex;
    _cfg.kwriteMethod = (DTKFDKwriteMethod)_kwriteControl.selectedSegmentIndex;
    DTKFDConfig *shared = [DTKFDConfig sharedConfig];
    shared.kernelExploit = _cfg.kernelExploit;
    shared.puafPages = _cfg.puafPages;
    shared.puafMethod = _cfg.puafMethod;
    shared.kreadMethod = _cfg.kreadMethod;
    shared.kwriteMethod = _cfg.kwriteMethod;
    [shared save];
    if (self.onClose) self.onClose(shared);
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end
