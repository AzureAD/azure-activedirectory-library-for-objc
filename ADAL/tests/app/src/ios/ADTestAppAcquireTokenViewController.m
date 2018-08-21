// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADTestAppAcquireTokenViewController.h"
#import "ADTestAppSettings.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTestAppAcquireLayoutBuilder.h"
#import "ADTestAppProfileViewController.h"
#import "ADTestAppClaimsPickerController.h"
#import "ADEnrollmentGateway.h"
#import "ADUserIdentifier.h"
#import "ADWebAuthController.h"
#import "ADEnrollmentGateway.h"

#ifdef AD_MAM_SDK_TESTING
#import <IntuneMAM/IntuneMAM.h>
#endif

#import <WebKit/WebKit.h>

@interface ADTestAppAcquireTokenViewController ()
#ifdef AD_MAM_SDK_TESTING
<UITextFieldDelegate, IntuneMAMComplianceDelegate, IntuneMAMEnrollmentDelegate>
#else
<UITextFieldDelegate>
#endif

@property (nonatomic) ADTestAppClaimsPickerController *claimsPickerController;

@end

@implementation ADTestAppAcquireTokenViewController
{
    UIView* _acquireSettingsView;
    UITextField* _userIdField;
    UITextField* _extraQueryParamsField;
    UITextField* _claimsField;
    UISegmentedControl* _userIdType;
    
    UISegmentedControl* _promptBehavior;
    
    UIButton* _profileButton;

    UISegmentedControl* _brokerEnabled;
    UISegmentedControl* _webViewType;
    UISegmentedControl* _fullScreen;
    UISegmentedControl* _validateAuthority;
    
    UITextView* _resultView;
    
    UIView* _authView;
    WKWebView* _webView;
    
    NSLayoutConstraint* _bottomConstraint;
    NSLayoutConstraint* _bottomConstraint2;
    
    BOOL _userIdEdited;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    UITabBarItem* tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Acquire" image:nil tag:0];
    [self setTabBarItem:tabBarItem];
    
    [self setEdgesForExtendedLayout:UIRectEdgeTop];
    
#ifdef AD_MAM_SDK_TESTING
    [[IntuneMAMComplianceManager instance] setDelegate:self];
    [[IntuneMAMEnrollmentManager instance] setDelegate:self];
#endif
    
    return self;
}

- (UIView*)createTwoItemLayoutView:(UIView*)item1
                             item2:(UIView*)item2
{
    item1.translatesAutoresizingMaskIntoConstraints = NO;
    item2.translatesAutoresizingMaskIntoConstraints = NO;
    
    UIView* view = [[UIView alloc] init];
    view.translatesAutoresizingMaskIntoConstraints = NO;
    [view addSubview:item1];
    [view addSubview:item2];
    
    NSDictionary* views = @{@"item1" : item1, @"item2" : item2 };
    NSArray* verticalConstraints1 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[item1(20)]|" options:0 metrics:NULL views:views];
    NSArray* verticalConstraints2 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[item2(20)]|" options:0 metrics:NULL views:views];
    NSArray* horizontalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[item1]-[item2]|" options:0 metrics:NULL views:views];
    
    [view addConstraints:verticalConstraints1];
    [view addConstraints:verticalConstraints2];
    [view addConstraints:horizontalConstraints];
    
    return view;
}

- (UIView*)createThreeItemLayoutView:(UIView*)item1
                               item2:(UIView*)item2
                               item3:(UIView*)item3
{
    item1.translatesAutoresizingMaskIntoConstraints = NO;
    item2.translatesAutoresizingMaskIntoConstraints = NO;
    item3.translatesAutoresizingMaskIntoConstraints = NO;
    
    UIView* view = [[UIView alloc] init];
    view.translatesAutoresizingMaskIntoConstraints = NO;
    [view addSubview:item1];
    [view addSubview:item2];
    [view addSubview:item3];
    
    NSDictionary* views = @{@"item1" : item1, @"item2" : item2, @"item3" : item3 };
    NSArray* verticalConstraints1 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[item1(20)]|" options:0 metrics:NULL views:views];
    NSArray* verticalConstraints2 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[item2(20)]|" options:0 metrics:NULL views:views];
    NSArray* verticalConstraints3 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[item3(20)]|" options:0 metrics:NULL views:views];
    NSArray* horizontalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[item1]-[item2]-[item3]|" options:0 metrics:NULL views:views];
    
    [view addConstraints:verticalConstraints1];
    [view addConstraints:verticalConstraints2];
    [view addConstraints:verticalConstraints3];
    [view addConstraints:horizontalConstraints];
    
    
    return view;
}

- (UIView *)createItemLayoutView:(NSArray<UIView *> *)items
{
    UIView *view = [UIView new];
    view.translatesAutoresizingMaskIntoConstraints = NO;

    NSMutableDictionary *viewsForConstraints = [NSMutableDictionary new];
    
    int count = 1;
    for (UIView *item in items)
    {
        item.translatesAutoresizingMaskIntoConstraints = NO;
        [view addSubview:item];
        
        NSString *name = [NSString stringWithFormat:@"item%d", count++];
        [viewsForConstraints setValue:item forKey:name];
    }
    
    // add constraints
    NSString *horizontalFormatStr = @"H:|";
    for (int i = 1; i<count; i++)
    {
        // vertical contraints
        NSString *verticalFormatStr = [NSString stringWithFormat:@"V:|[item%d(20)]|", i];
        NSArray *verticalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:verticalFormatStr options:0 metrics:NULL views:viewsForConstraints];
        [view addConstraints:verticalConstraints];
        
        // horizontal contraints
        if (count > 1)
        {
            horizontalFormatStr = [horizontalFormatStr stringByAppendingString:@"-"];
        }
        horizontalFormatStr = [horizontalFormatStr stringByAppendingString:[NSString stringWithFormat:@"[item%d]", i]];
    }
    horizontalFormatStr = [horizontalFormatStr stringByAppendingString:@"|"];

    NSArray *horizontalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:horizontalFormatStr options:0 metrics:NULL views:viewsForConstraints];
    [view addConstraints:horizontalConstraints];
    
    return view;
}

- (UIView*)createSettingsAndResultView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    UIScrollView* scrollView = [[UIScrollView alloc] initWithFrame:screenFrame];
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.scrollEnabled = YES;
    scrollView.showsVerticalScrollIndicator = YES;
    scrollView.showsHorizontalScrollIndicator = NO;
    scrollView.userInteractionEnabled = YES;
    ADTestAppAcquireLayoutBuilder* layout = [ADTestAppAcquireLayoutBuilder new];
    
    _userIdField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 400, 20)];
    _userIdField.borderStyle = UITextBorderStyleRoundedRect;
    _userIdField.delegate = self;
    [layout addControl:_userIdField title:@"userId"];
    
    _userIdType = [[UISegmentedControl alloc] initWithItems:@[@"Optional", @"Required", @"Unique"]];
    _userIdType.selectedSegmentIndex = 0;
    [layout addControl:_userIdType title:@"idType"];
    
    _promptBehavior = [[UISegmentedControl alloc] initWithItems:@[@"Always", @"Auto", @"Force"]];
    _promptBehavior.selectedSegmentIndex = 0;
    [layout addControl:_promptBehavior title:@"prompt"];
    
    _profileButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_profileButton setTitle:ADTestAppSettings.currentProfileTitle forState:UIControlStateNormal];
    [_profileButton addTarget:self action:@selector(changeProfile:) forControlEvents:UIControlEventTouchUpInside];
    _profileButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    [layout addControl:_profileButton title:@"profile"];
    
    _webViewType = [[UISegmentedControl alloc] initWithItems:@[@"Passed In", @"ADAL"]];
    _webViewType.selectedSegmentIndex = 1;
    [layout addControl:_webViewType title:@"webView"];
    
    _fullScreen = [[UISegmentedControl alloc] initWithItems:@[@"Yes", @"No"]];
    _fullScreen.selectedSegmentIndex = 0;
    [layout addControl:_fullScreen title:@"fullScreen"];
    
    _brokerEnabled = [[UISegmentedControl alloc] initWithItems:@[@"Disabled", @"Auto"]];
    [_brokerEnabled setSelectedSegmentIndex:0];
    [layout addControl:_brokerEnabled title:@"broker"];
    
    _validateAuthority = [[UISegmentedControl alloc] initWithItems:@[@"Yes", @"No"]];
    [layout addControl:_validateAuthority title:@"valAuth"];
    
    _extraQueryParamsField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 400, 20)];
    _extraQueryParamsField.borderStyle = UITextBorderStyleRoundedRect;
    _extraQueryParamsField.delegate = self;
    [layout addControl:_extraQueryParamsField title:@"EQP"];
    
    _claimsField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 400, 20)];
    _claimsField.borderStyle = UITextBorderStyleRoundedRect;
    _claimsField.delegate = self;
    
    UIButton *claimsButton = [UIButton buttonWithType:UIButtonTypeSystem];
    claimsButton.translatesAutoresizingMaskIntoConstraints = NO;
    [claimsButton setTitle:@"Claims" forState:UIControlStateNormal];
    [claimsButton addTarget:self action:@selector(onClaimsButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [layout addControl:_claimsField button:claimsButton];
    
    UIButton* clearCookies = [UIButton buttonWithType:UIButtonTypeSystem];
    [clearCookies setTitle:@"Clear Cookies" forState:UIControlStateNormal];
    [clearCookies addTarget:self action:@selector(clearCookies:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton* clearCache = [UIButton buttonWithType:UIButtonTypeSystem];
    [clearCache setTitle:@"Clear Cache" forState:UIControlStateNormal];
    [clearCache addTarget:self action:@selector(clearCache:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton* wipeUpn = [UIButton buttonWithType:UIButtonTypeSystem];
    [wipeUpn setTitle:@"Wipe cache" forState:UIControlStateNormal];
    [wipeUpn addTarget:self action:@selector(wipeCache:) forControlEvents:UIControlEventTouchUpInside];
    
    
    UIView* clearButtonsView = [self createThreeItemLayoutView:clearCookies item2:clearCache item3:wipeUpn];
    [layout addCenteredView:clearButtonsView key:@"clearButtons"];
    
    UIButton *mamEnroll = [UIButton buttonWithType:UIButtonTypeSystem];
    [mamEnroll setTitle:@"MAM Enroll" forState:UIControlStateNormal];
    [mamEnroll addTarget:self action:@selector(mamEnroll:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *mamUnenroll = [UIButton buttonWithType:UIButtonTypeSystem];
    [mamUnenroll setTitle:@"MAM Unenroll" forState:UIControlStateNormal];
    [mamUnenroll addTarget:self action:@selector(mamUnenroll:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *mamEnrollIds = [UIButton buttonWithType:UIButtonTypeSystem];
    [mamEnrollIds setTitle:@"MAM Enroll IDs" forState:UIControlStateNormal];
    [mamEnrollIds addTarget:self action:@selector(mamEnrollIds:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *mamDelEnrollIds = [UIButton buttonWithType:UIButtonTypeSystem];
    [mamDelEnrollIds setTitle:@"Delete MAM IDs" forState:UIControlStateNormal];
    [mamDelEnrollIds addTarget:self action:@selector(mamDelEnrollIds:) forControlEvents:UIControlEventTouchUpInside];
    
    NSArray *buttons = @[mamEnroll, mamUnenroll, mamEnrollIds, mamDelEnrollIds];
    UIView *mamButtonsView = [self createItemLayoutView:buttons];
    [layout addCenteredView:mamButtonsView key:@"mamButtons"];
    
    _resultView = [[UITextView alloc] init];
    _resultView.layer.borderWidth = 1.0f;
    _resultView.layer.borderColor = [UIColor colorWithRed:0.9f green:0.9f blue:0.9f alpha:1.0f].CGColor;
    _resultView.layer.cornerRadius = 8.0f;
    _resultView.backgroundColor = [UIColor colorWithRed:0.96f green:0.96f blue:0.96f alpha:1.0f];
    _resultView.editable = NO;
    _resultView.text = [NSString stringWithFormat:@"ADAL %@", ADAL_VERSION_NSSTRING];
    [layout addView:_resultView key:@"result"];
    
    UIView* contentView = [layout contentView];
    [scrollView addSubview:contentView];
    
    NSDictionary* views = @{ @"contentView" : contentView, @"scrollView" : scrollView };
    [scrollView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|[contentView]|" options:0 metrics:nil views:views]];
    [scrollView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|[contentView]|" options:0 metrics:nil views:views]];
    [scrollView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"[contentView(==scrollView)]" options:0 metrics:nil views:views]];
    
    return scrollView;
}

- (UIView *)createAcquireButtonsView
{
    UIButton* acquireButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [acquireButton setTitle:@"acquireToken" forState:UIControlStateNormal];
    [acquireButton addTarget:self action:@selector(acquireTokenInteractive:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton* acquireSilentButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [acquireSilentButton setTitle:@"acquireTokenSilent" forState:UIControlStateNormal];
    [acquireSilentButton addTarget:self action:@selector(acquireTokenSilent:) forControlEvents:UIControlEventTouchUpInside];
    
    UIView* acquireButtonsView = [self createTwoItemLayoutView:acquireButton item2:acquireSilentButton];
    UIVisualEffect* blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleLight];
    UIVisualEffectView* acquireBlurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    acquireBlurView.translatesAutoresizingMaskIntoConstraints = NO;
    [acquireBlurView.contentView addSubview:acquireButtonsView];
    
    // Constraint to center the acquire buttons in the blur view
    [acquireBlurView addConstraint:[NSLayoutConstraint constraintWithItem:acquireButtonsView
                                                                attribute:NSLayoutAttributeCenterX
                                                                relatedBy:NSLayoutRelationEqual
                                                                   toItem:acquireBlurView
                                                                attribute:NSLayoutAttributeCenterX
                                                               multiplier:1.0
                                                                 constant:0.0]];
    NSDictionary* views = @{ @"buttons" : acquireButtonsView };
    [acquireBlurView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-6-[buttons]-6-|" options:0 metrics:nil views:views]];
    
    return acquireBlurView;
}

- (UIView *)createWebOverlay
{
    UIVisualEffect* blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleLight];
    UIVisualEffectView* blurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    blurView.translatesAutoresizingMaskIntoConstraints = NO;
    blurView.layer.borderWidth = 1.0f;
    blurView.layer.borderColor = [UIColor colorWithRed:0.9f green:0.9f blue:0.9f alpha:1.0f].CGColor;
    blurView.layer.cornerRadius = 8.0f;
    blurView.clipsToBounds = YES;
    
    UIView* contentView = blurView.contentView;
    
    _webView = [[WKWebView alloc] init];
    _webView.translatesAutoresizingMaskIntoConstraints = NO;
    [contentView addSubview:_webView];
    
    UIButton* cancelButton = [UIButton buttonWithType:UIButtonTypeSystem];
    cancelButton.translatesAutoresizingMaskIntoConstraints = NO;
    [cancelButton setTitle:@"Cancel" forState:UIControlStateNormal];
    [cancelButton addTarget:self action:@selector(cancelAuth:) forControlEvents:UIControlEventTouchUpInside];
    [contentView addSubview:cancelButton];
    
    NSDictionary* views = @{ @"webView" : _webView, @"cancelButton" : cancelButton };
    [contentView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-8-[webView]-[cancelButton]-8-|" options:0 metrics:nil views:views]];
    [contentView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|-8-[webView]-|" options:0 metrics:nil views:views]];
    [contentView addConstraint:[NSLayoutConstraint constraintWithItem:cancelButton
                                                            attribute:NSLayoutAttributeCenterX
                                                            relatedBy:NSLayoutRelationEqual
                                                               toItem:contentView
                                                            attribute:NSLayoutAttributeCenterX
                                                           multiplier:1.0
                                                             constant:0.0]];
    
    return blurView;
}


- (void)loadView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    UIView* mainView = [[UIView alloc] initWithFrame:screenFrame];
    
    UIView* settingsView = [self createSettingsAndResultView];
    [mainView addSubview:settingsView];
    
    UIView* acquireBlurView = [self createAcquireButtonsView];
    [mainView addSubview:acquireBlurView];
    
    _authView = [self createWebOverlay];
    _authView.hidden = YES;
    [mainView addSubview:_authView];
    
    self.view = mainView;
    
    NSDictionary* views = @{ @"settings" : settingsView, @"acquire" : acquireBlurView, @"authView" : _authView };
    // Set up constraints for the web overlay
    [mainView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-34-[authView]-10-|" options:0 metrics:nil views:views]];
    [mainView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|-10-[authView]-10-|" options:0 metrics:nil views:views]];
    
    // Set up constraints to make the settings scroll view take up the whole screen
    [mainView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|[settings]|" options:0 metrics:nil views:views]];
    [mainView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|[settings(>=200)]" options:0 metrics:nil views:views]];
    _bottomConstraint2 = [NSLayoutConstraint constraintWithItem:settingsView
                                                      attribute:NSLayoutAttributeBottom
                                                      relatedBy:NSLayoutRelationEqual
                                                         toItem:self.bottomLayoutGuide
                                                      attribute:NSLayoutAttributeTop
                                                     multiplier:1.0
                                                       constant:0];
    [mainView addConstraint:_bottomConstraint2];
    
    
    // And more constraints to make the acquire buttons view float on top
    [mainView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|[acquire]|" options:0 metrics:nil views:views]];
    
    // This constraint is the one that gets adjusted when the keyboard hides or shows. It moves the acquire buttons to make sure
    // they remain in view above the keyboard
    _bottomConstraint = [NSLayoutConstraint constraintWithItem:acquireBlurView
                                                     attribute:NSLayoutAttributeBottom
                                                     relatedBy:NSLayoutRelationEqual
                                                        toItem:self.bottomLayoutGuide
                                                     attribute:NSLayoutAttributeTop
                                                    multiplier:1.0
                                                      constant:0];
    [mainView addConstraint:_bottomConstraint];
    [self updateSettings];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(profileDidChange:) name:ADTestAppProfileChangedNotification object:nil];
}

- (void)profileDidChange:(NSNotification *)notification
{
    [self updateSettings];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField
{
    [textField resignFirstResponder];
    return YES;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keyboardWillShow:)
                                                 name:UIKeyboardWillShowNotification
                                               object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keyboardWillHide:)
                                                 name:UIKeyboardWillHideNotification
                                               object:nil];
    
    self.claimsPickerController = [ADTestAppClaimsPickerController alertControllerWithTitle:@"" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    self.claimsPickerController.claimsTextField = _claimsField;
    self.claimsPickerController.claims = @{@"MFA" : @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D", @"MAM CA" : @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%22d77e91f0-fc60-45e4-97b8-14a1337faa28%22%5D%7D%7D%7D", @"Device ID": @"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D"};
}

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}

- (void)keyboardWillShow:(NSNotification *)aNotification
{
    NSDictionary* userInfo = aNotification.userInfo;
    NSTimeInterval duration = [userInfo[UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    UIViewAnimationCurve curve = [userInfo[UIKeyboardAnimationCurveUserInfoKey] integerValue];
    
    CGRect keyboardFrameEnd = [userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    keyboardFrameEnd = [self.view convertRect:keyboardFrameEnd fromView:nil];
    
    [UIView animateWithDuration:duration delay:0 options:UIViewAnimationOptionBeginFromCurrentState | curve animations:^{
        _bottomConstraint.constant = -keyboardFrameEnd.size.height + 49.0; // 49.0 is the height of a tab bar
        _bottomConstraint2.constant = -keyboardFrameEnd.size.height + 49.0;
        [self.view layoutIfNeeded];
    } completion:nil];
}

- (void)keyboardWillHide:(NSNotification *)note {
    NSDictionary *userInfo = note.userInfo;
    NSTimeInterval duration = [userInfo[UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    UIViewAnimationCurve curve = [userInfo[UIKeyboardAnimationCurveUserInfoKey] integerValue];
    
    CGRect keyboardFrameEnd = [userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    keyboardFrameEnd = [self.view convertRect:keyboardFrameEnd fromView:nil];
    
    [UIView animateWithDuration:duration delay:0 options:UIViewAnimationOptionBeginFromCurrentState | curve animations:^{
        _bottomConstraint.constant = 0;
        _bottomConstraint2.constant = 0;
        [self.view layoutIfNeeded];
    } completion:nil];
}

- (void)viewWillAppear:(BOOL)animated
{
    
}

- (void)updateSettings
{
    [_profileButton setTitle:[ADTestAppSettings currentProfileTitle] forState:UIControlStateNormal];
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    
    _userIdField.text = settings.defaultUser;
    _extraQueryParamsField.text = settings.extraQueryParameters;
    _claimsField.text = nil;
    
    self.navigationController.navigationBarHidden = YES;
    _validateAuthority.selectedSegmentIndex = settings.validateAuthority ? 0 : 1;
    _brokerEnabled.selectedSegmentIndex = settings.enableBroker ? 1 : 0;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.

}

- (ADUserIdentifier*)identifier
{
    NSString* userId = [_userIdField text];
    
    if (!userId || [userId isEqualToString:@""])
    {
        return nil;
    }
    
    NSString* userIdType = [_userIdType titleForSegmentAtIndex:[_userIdType selectedSegmentIndex]];
    
    ADUserIdentifierType idType = OptionalDisplayableId;
    
    if ([userIdType isEqualToString:@"Optional"])
    {
        idType = OptionalDisplayableId;
    }
    else if ([userIdType isEqualToString:@"Required"])
    {
        idType = RequiredDisplayableId;
    }
    else if ([userIdType isEqualToString:@"Unique"])
    {
        idType = UniqueId;
    }
    else
    {
        @throw @"Unexpected idtype";
    }
    
    return [ADUserIdentifier identifierWithId:userId type:idType];
}

- (ADCredentialsType)credType
{
    NSString* credType = [_brokerEnabled titleForSegmentAtIndex:[_brokerEnabled selectedSegmentIndex]];
    
    if ([credType isEqualToString:@"Disabled"])
    {
        return AD_CREDENTIALS_EMBEDDED;
    }
    else if ([credType isEqualToString:@"Auto"])
    {
        return AD_CREDENTIALS_AUTO;
    }
    else
    {
        @throw @"Unexpected cred type";
    }
}

- (BOOL)embeddedWebView
{
    NSString* webViewType = [_webViewType titleForSegmentAtIndex:[_webViewType selectedSegmentIndex]];
    
    if ([webViewType isEqualToString:@"ADAL"])
    {
        return NO;
    }
    else if ([webViewType isEqualToString:@"Passed In"])
    {
        return YES;
    }
    else
    {
        @throw @"unexpected webview type";
    }
}

- (void)updateResultView:(ADAuthenticationResult*)result
{
    NSString* resultStatus = nil;
    
    switch (result.status)
    {
        case AD_SUCCEEDED : resultStatus = @"AD_SUCCEEDED"; break;
        case AD_FAILED : resultStatus = @"AD_FAILED"; break;
        case AD_USER_CANCELLED : resultStatus = @"AD_USER_CANCELLED"; break;
        default:
            resultStatus = [NSString stringWithFormat:@"Unknown (%d)", result.status];
            break;
    }
    
    NSString* resultText = [NSString stringWithFormat:@"{\n\tstatus = %@;\n\terror = %@\n\tcorrelation ID = %@\n\ttokenCacheItem = %@\n\tauthority = %@\n}", resultStatus, result.error, result.correlationId, result.tokenCacheItem, result.authority];
    
    [_resultView setText:resultText];
    
    printf("%s", [resultText UTF8String]);
}

- (ADPromptBehavior)promptBehavior
{
    NSString* label = [_promptBehavior titleForSegmentAtIndex:_promptBehavior.selectedSegmentIndex];
    
    if ([label isEqualToString:@"Always"])
        return AD_PROMPT_ALWAYS;
    if ([label isEqualToString:@"Auto"])
        return AD_PROMPT_AUTO;
    if ([label isEqualToString:@"Force"])
        return AD_FORCE_PROMPT;
    
    @throw @"Do not recognize prompt behavior";
}

- (void)acquireTokenInteractive:(id)sender
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    NSString* authority = [settings authority];
    NSString* resource = [settings resource];
    NSString* clientId = [settings clientId];
    NSURL* redirectUri = [settings redirectUri];
    NSString* extraQueryParameters = _extraQueryParamsField.text;
    NSString* claims = _claimsField.text;
    
    ADUserIdentifier* identifier = [self identifier];
    ADCredentialsType credType = [self credType];
    
    BOOL validateAuthority = _validateAuthority.selectedSegmentIndex == 0;
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:validateAuthority
                                                                                    error:&error];
    if (!context)
    {
        NSString* resultText = [NSString stringWithFormat:@"Failed to create AuthenticationContext:\n%@", error];
        [_resultView setText:resultText];
        return;
    }
    
    [context setCredentialsType:credType];
    
    if ([self embeddedWebView])
    {
        [context setWebView:_webView];
        //[_authView setFrame:self.view.frame];
        
        [UIView animateWithDuration:0.5 animations:^{
            [_acquireSettingsView setHidden:YES];
            [_authView setHidden:NO];
        }];
    }
    
    __block BOOL fBlockHit = NO;
    
    [context acquireTokenWithResource:resource
                             clientId:clientId
                          redirectUri:redirectUri
                       promptBehavior:[self promptBehavior]
                       userIdentifier:identifier
                 extraQueryParameters:extraQueryParameters
                               claims:claims
                      completionBlock:^(ADAuthenticationResult *result)
    {
        if (fBlockHit)
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Error!"
                                                                               message:@"Completion block was hit multiple times!"
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                
                [self presentViewController:alert animated:YES completion:nil];
            });
            
            return;
        }
        fBlockHit = YES;
        
        
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateResultView:result];
            
            [_webView loadHTMLString:@"<html><head></head><body>done!</body></html>" baseURL:nil];
            [_authView setHidden:YES];
            [self.view setNeedsDisplay];
            
            [[NSNotificationCenter defaultCenter] postNotificationName:ADTestAppCacheChangeNotification object:self];
        });
    }];
    
}

- (IBAction)onClaimsButtonTapped:(UIButton *)sender
{
    self.claimsPickerController.popoverPresentationController.sourceView = sender;
    self.claimsPickerController.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:self.claimsPickerController animated:YES completion:nil];
}

- (IBAction)cancelAuth:(id)sender
{
    [ADWebAuthController cancelCurrentWebAuthSession];
}

- (IBAction)acquireTokenSilent:(id)sender
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    NSString* authority = [settings authority];
    NSString* resource = [settings resource];
    NSString* clientId = [settings clientId];
    NSURL* redirectUri = [settings redirectUri];
    ADUserIdentifier* identifier = [self identifier];
    BOOL validateAuthority = _validateAuthority.selectedSegmentIndex == 0;
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority validateAuthority:validateAuthority error:&error];
    if (!context)
    {
        NSString* resultText = [NSString stringWithFormat:@"Failed to create AuthenticationContext:\n%@", error];
        [_resultView setText:resultText];
        return;
    }
    
    __block BOOL fBlockHit = NO;
    
    [context acquireTokenSilentWithResource:resource clientId:clientId redirectUri:redirectUri userId:identifier.userId completionBlock:^(ADAuthenticationResult *result)
    {
        if (fBlockHit)
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Error!"
                                                                               message:@"Completion block was hit multiple times!"
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                
                [self presentViewController:alert animated:YES completion:nil];
            });
            return;
        }
        fBlockHit = YES;
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateResultView:result];
            
            [[NSNotificationCenter defaultCenter] postNotificationName:ADTestAppCacheChangeNotification object:self];
        });
    }];
}

- (IBAction)clearCache:(id)sender
{
    NSError *error = nil;
    [[ADKeychainTokenCache defaultKeychainCache] testRemoveAll:&error];
    
    if (!error)
    {
        _resultView.text = @"Successfully cleared cache.";
    }
    else
    {
        _resultView.text = [NSString stringWithFormat:@"Failed to clear cache, error = %@", error];
    }
}

- (IBAction)clearCookies:(id)sender
{
    NSHTTPCookieStorage* cookieStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = cookieStore.cookies;
    for (NSHTTPCookie* cookie in cookies)
    {
        [cookieStore deleteCookie:cookie];
    }
    
    NSSet *allTypes = [WKWebsiteDataStore allWebsiteDataTypes];
    [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:allTypes
                                               modifiedSince:[NSDate dateWithTimeIntervalSince1970:0]
                                           completionHandler:^{
                                               NSLog(@"Completed!");
                                           }];
    
    _resultView.text = [NSString stringWithFormat:@"Cleared %lu cookies.", (unsigned long)cookies.count];
}

- (IBAction)wipeCache:(id)sender
{
    NSString* userId = [_userIdField text];
    
    if (!userId || [userId isEqualToString:@""])
    {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Error!"
                                                                       message:@"Wipe cache needs a userId"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"close" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    ADAuthenticationError *error = nil;
    if (![[ADKeychainTokenCache defaultKeychainCache] wipeAllItemsForUserId:userId error:&error])
    {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Error!"
                                                                       message:error.localizedDescription
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"close" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    _resultView.text = [NSString stringWithFormat:@"Wiped cache for %@.", userId];
    
}

- (IBAction)changeProfile:(id)sender
{
    [self.navigationController pushViewController:[ADTestAppProfileViewController sharedProfileViewController] animated:YES];
}

- (IBAction)mamEnroll:(id)sender
{
#ifdef AD_MAM_SDK_TESTING
    if ([NSString msidIsStringNilOrBlank:self.identifier.userId])
    {
        _resultView.text = [NSString stringWithFormat:@"Please specify user id before clicking register!"];
        return;
    }
    
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    [[IntuneMAMPolicyManager instance] setAadAuthorityUriOverride:settings.authority];
    [[IntuneMAMPolicyManager instance] setAadClientIdOverride:settings.clientId];
    [[IntuneMAMPolicyManager instance] setAadRedirectUriOverride:settings.redirectUri.absoluteString];
    
    [[IntuneMAMComplianceManager instance] remediateComplianceForIdentity:self.identifier.userId silent:NO];
#endif
}

- (IBAction)mamUnenroll:(id)sender
{
#ifdef AD_MAM_SDK_TESTING
    if ([NSString msidIsStringNilOrBlank:self.identifier.userId])
    {
        _resultView.text = [NSString stringWithFormat:@"Please specify user id before clicking unregister!"];
        return;
    }
    
    _resultView.text = [NSString stringWithFormat:@"Sending Unenroll request to MAM SDK..."];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [[IntuneMAMEnrollmentManager instance] deRegisterAndUnenrollAccount:self.identifier.userId withWipe:YES];
    });
#endif
}

- (IBAction)mamEnrollIds:(id)sender
{
#ifdef AD_MAM_SDK_TESTING
    _resultView.text = [ADEnrollmentGateway allEnrollmentIdsJSON];
#endif
}

- (IBAction)mamDelEnrollIds:(id)sender
{
#ifdef AD_MAM_SDK_TESTING
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"intune_app_protection_enrollment_id_V1"];
    _resultView.text = [ADEnrollmentGateway allEnrollmentIdsJSON];
#endif
}

#ifdef AD_MAM_SDK_TESTING
- (void)identity:(NSString*)identity hasComplianceStatus:(IntuneMAMComplianceStatus)status withErrorString:(NSString *)error
{
    dispatch_async(dispatch_get_main_queue(), ^{
        _resultView.text = [NSString stringWithFormat:@"MAM Enrollment for %@ with status: %lu, error: %@", identity, (unsigned long)status, error];
    });
}

- (void)unenrollRequestWithStatus:(IntuneMAMEnrollmentStatus *_Nonnull)status
{
    dispatch_async(dispatch_get_main_queue(), ^{
        _resultView.text = [NSString stringWithFormat:@"Unenrollment status for %@: success: %@, status code: %lu, errorString: %@, error: %@", status.identity, status.didSucceed ? @"YES":@"NO", (unsigned long)status.statusCode, status.errorString, status.error];
    });
}
#endif

@end
