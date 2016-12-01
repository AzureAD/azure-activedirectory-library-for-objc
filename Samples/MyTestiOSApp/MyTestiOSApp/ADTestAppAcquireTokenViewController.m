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

@interface ADTestAppAcquireTokenViewController ()

@end

// Apple provides a lot of this in UIStackView in iOS 9, but prior to that we need to build it by hand
@interface ADTestAppSettingsLayoutBuilder : NSObject
{
    UIView* _contentView;
    NSMutableDictionary* _views;
    NSMutableArray* _keys;
    CGRect _screenRect;
}

- (void)addControl:(UIControl *)control
             title:(NSString *)title;

- (void)addView:(UIView*)view key:(NSString *)key;

- (void)addCenteredView:(UIView *)view
                    key:(NSString *)key;

- (UIView*)contentView;

@end

@implementation ADTestAppSettingsLayoutBuilder

- (id)init
{
    if (!(self = [super init]))
        return nil;
    
    _screenRect = UIScreen.mainScreen.bounds;
    _contentView = [[UIView alloc] initWithFrame:_screenRect];
    _contentView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    
    _views = [NSMutableDictionary new];
    _keys = [NSMutableArray new];
    
    return self;
}

- (void)addControl:(UIControl *)control
             title:(NSString *)title
{
    UIView* view = [[UIView alloc] init];
    UILabel* label = [[UILabel alloc] init];
    label.textColor = UIColor.blackColor;
    label.text = title;
    label.font = [UIFont systemFontOfSize:12.0];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.textAlignment = NSTextAlignmentRight;
    
    [view addSubview:label];
    
    control.translatesAutoresizingMaskIntoConstraints = NO;
    [view addSubview:control];
    
    NSDictionary* views = @{ @"label" : label, @"control" : control };
    NSArray* verticalConstraints1 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[label]|" options:0 metrics:NULL views:views];
    NSArray* verticalConstraints2 = [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[control(29)]|" options:0 metrics:NULL views:views];
    NSArray* horizontalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[label(60)]-[control]|" options:NSLayoutFormatAlignAllCenterY metrics:NULL views:views];
    
    [view addConstraints:verticalConstraints1];
    [view addConstraints:verticalConstraints2];
    [view addConstraints:horizontalConstraints];
    
    [self addView:view key:title];
}

- (void)addViewInternal:(UIView*)view key:(NSString *)key
{
    view.translatesAutoresizingMaskIntoConstraints = NO;
    [_contentView addSubview:view];
    [_views setObject:view forKey:key];
    [_keys addObject:key];
}

- (void)addView:(UIView*)view key:(NSString *)key
{
    [self addViewInternal:view key:key];
    
    NSString* horizontalConstraint = [NSString stringWithFormat:@"H:|-6-[%@]-6-|", key];
    NSArray* horizontalConstraints2 = [NSLayoutConstraint constraintsWithVisualFormat:horizontalConstraint options:0 metrics:NULL views:_views];
    [_contentView addConstraints:horizontalConstraints2];
}

- (void)addCenteredView:(UIView *)view key:(NSString *)key
{
    [self addViewInternal:view key:key];
    
    NSLayoutConstraint* centerConstraint =
    [NSLayoutConstraint constraintWithItem:view
                                 attribute:NSLayoutAttributeCenterX
                                 relatedBy:NSLayoutRelationEqual
                                    toItem:_contentView
                                 attribute:NSLayoutAttributeCenterX
                                multiplier:1.0
                                  constant:0.0];
    [_contentView addConstraint:centerConstraint];
}

- (UIView*)contentView
{
    if (_keys.count == 0)
    {
        return _contentView;
    }
    
    NSMutableString* verticalConstraint = [NSMutableString new];
    [verticalConstraint appendString:@"V:|-24-"];
    
    for (int i = 0; i < _keys.count - 1; i++)
    {
        NSString* key = _keys[i];
        [verticalConstraint appendFormat:@"[%@]-", key];
    }
    
    NSString* lastKey = _keys.lastObject;
    [verticalConstraint appendFormat:@"[%@(>=200)]-36-|", lastKey];
    
    //[verticalConstraint appendString:@"-|"];
    NSArray* verticalConstraints = [NSLayoutConstraint constraintsWithVisualFormat:verticalConstraint options:0 metrics:NULL views:_views];
    [_contentView addConstraints:verticalConstraints];
    
    return _contentView;
}

@end

@implementation ADTestAppAcquireTokenViewController
{
    IBOutlet UIView* _acquireSettingsView;
    IBOutlet UITextField* _userIdField;
    IBOutlet UISegmentedControl* _userIdType;
    
    UISegmentedControl* _promptBehavior;

    IBOutlet UISegmentedControl* _brokerEnabled;
    IBOutlet UISegmentedControl* _webViewType;
    IBOutlet UISegmentedControl* _fullScreen;
    IBOutlet UISegmentedControl* _validateAuthority;
    
    IBOutlet UITextView* _resultView;
    
    IBOutlet UIView* _authView;
    IBOutlet UIWebView* _webView;
    
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

- (UIView*)createSettingsAndResultView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    UIScrollView* scrollView = [[UIScrollView alloc] initWithFrame:screenFrame];
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.scrollEnabled = YES;
    scrollView.showsVerticalScrollIndicator = YES;
    scrollView.showsHorizontalScrollIndicator = NO;
    scrollView.userInteractionEnabled = YES;
    ADTestAppSettingsLayoutBuilder* layout = [ADTestAppSettingsLayoutBuilder new];
    
    _userIdField = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 400, 20)];
    _userIdField.borderStyle = UITextBorderStyleRoundedRect;
    [layout addControl:_userIdField title:@"userId"];
    
    _userIdType = [[UISegmentedControl alloc] initWithItems:@[@"Optional", @"Required", @"Unique"]];
    _userIdType.selectedSegmentIndex = 0;
    [layout addControl:_userIdType title:@"idType"];
    
    _promptBehavior = [[UISegmentedControl alloc] initWithItems:@[@"Always", @"Auto"]];
    _promptBehavior.selectedSegmentIndex = 0;
    [layout addControl:_promptBehavior title:@"prompt"];
    
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
    
    UIButton* clearCookies = [UIButton buttonWithType:UIButtonTypeSystem];
    [clearCookies setTitle:@"Clear Cookies" forState:UIControlStateNormal];
    [clearCookies addTarget:self action:@selector(clearCookies:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton* clearCache = [UIButton buttonWithType:UIButtonTypeSystem];
    [clearCache setTitle:@"Clear Cache" forState:UIControlStateNormal];
    [clearCache addTarget:self action:@selector(clearCache:) forControlEvents:UIControlEventTouchUpInside];
    
    UIView* clearButtonsView = [self createTwoItemLayoutView:clearCookies item2:clearCache];
    [layout addCenteredView:clearButtonsView key:@"clearButtons"];
    
    _resultView = [[UITextView alloc] init];
    _resultView.layer.borderWidth = 1.0f;
    _resultView.layer.borderColor = [UIColor colorWithRed:0.9f green:0.9f blue:0.9f alpha:1.0f].CGColor;
    _resultView.layer.cornerRadius = 8.0f;
    _resultView.backgroundColor = [UIColor colorWithRed:0.96f green:0.96f blue:0.96f alpha:1.0f];
    _resultView.editable = NO;
    [layout addView:_resultView key:@"result"];
    
    UIView* contentView = [layout contentView];
    [scrollView addSubview:contentView];
    scrollView.contentSize = contentView.bounds.size;
    
    return scrollView;
}


- (void)loadView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    UIView* mainView = [[UIView alloc] initWithFrame:screenFrame];
    
    UIView* settingsView = [self createSettingsAndResultView];
    [mainView addSubview:settingsView];
    
    UIButton* acquireButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [acquireButton setTitle:@"acquire" forState:UIControlStateNormal];
    [acquireButton addTarget:self action:@selector(acquireTokenInteractive:) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton* acquireSilentButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [acquireSilentButton setTitle:@"acquireSilent" forState:UIControlStateNormal];
    [acquireSilentButton addTarget:self action:@selector(acquireTokenSilent:) forControlEvents:UIControlEventTouchUpInside];
    
    UIView* acquireButtonsView = [self createTwoItemLayoutView:acquireButton item2:acquireSilentButton];
    UIVisualEffect* blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleLight];
    UIVisualEffectView* acquireBlurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    acquireBlurView.translatesAutoresizingMaskIntoConstraints = NO;
    [acquireBlurView.contentView addSubview:acquireButtonsView];
    
    NSDictionary* views = @{ @"settings" : settingsView, @"acquire" : acquireBlurView, @"buttons" : acquireButtonsView };
    
    // Constraint to center the acquire buttons in the blur view
    [acquireBlurView addConstraint:[NSLayoutConstraint constraintWithItem:acquireButtonsView
                                                                attribute:NSLayoutAttributeCenterX
                                                                relatedBy:NSLayoutRelationEqual
                                                                   toItem:acquireBlurView
                                                                attribute:NSLayoutAttributeCenterX
                                                               multiplier:1.0
                                                                 constant:0.0]];
    [acquireBlurView addConstraints:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-6-[buttons]-6-|" options:0 metrics:nil views:views]];
    
    
    [mainView addSubview:acquireBlurView];
    
    self.view = mainView;
    
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
    
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
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
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    if (!_userIdEdited)
    {
        [_userIdField setText:settings.defaultUser];
    }
    
    [_validateAuthority setSelectedSegmentIndex:settings.validateAuthority ? 0 : 1];
    [_brokerEnabled setSelectedSegmentIndex:settings.enableBroker ? 1 : 0];
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
    
    NSString* resultText = [NSString stringWithFormat:@"{\n\tstatus = %@;\n\terror = %@\n\tcorrelation ID = %@\n\ttokenCacheItem = %@\n}", resultStatus, result.error, result.correlationId, result.tokenCacheItem];
    
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
    
    @throw @"Do not recognize prompt behavior";
}

- (void)acquireTokenInteractive:(id)sender
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    NSString* authority = [settings authority];
    NSString* resource = [settings resource];
    NSString* clientId = [settings clientId];
    NSURL* redirectUri = [settings redirectUri];
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
        [_authView setFrame:self.view.frame];
        
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
                 extraQueryParameters:nil
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
            
            if ([_acquireSettingsView isHidden])
            {
                [_webView loadHTMLString:@"<html><head></head><body>done!</body></html>" baseURL:nil];
                [_authView setHidden:YES];
                [_acquireSettingsView setHidden:NO];
                [self.view setNeedsDisplay];
            }
            
            [[NSNotificationCenter defaultCenter] postNotificationName:ADTestAppCacheChangeNotification object:self];
        });
    }];
    
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
    NSDictionary* query = [[ADKeychainTokenCache defaultKeychainCache] defaultKeychainQuery];
    OSStatus status = SecItemDelete((CFDictionaryRef)query);
    
    _resultView.text = [NSString stringWithFormat:@"Deleted keychain items (%d)", (int)status];
}

- (IBAction)clearCookies:(id)sender
{
    NSHTTPCookieStorage* cookieStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = cookieStore.cookies;
    for (NSHTTPCookie* cookie in cookies)
    {
        [cookieStore deleteCookie:cookie];
    }
    
    _resultView.text = [NSString stringWithFormat:@"Cleared %lu cookies.", (unsigned long)cookies.count];
}

@end
