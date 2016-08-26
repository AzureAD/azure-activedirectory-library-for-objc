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

@interface ADTestAppAcquireTokenViewController ()

@end

@implementation ADTestAppAcquireTokenViewController
{
    IBOutlet UIView* _acquireSettingsView;
    IBOutlet UITextField* _userIdField;
    IBOutlet UISegmentedControl* _userIdType;

    IBOutlet UISegmentedControl* _credentialsType;
    IBOutlet UISegmentedControl* _webViewType;
    IBOutlet UISegmentedControl* _fullScreen;
    IBOutlet UISegmentedControl* _validateAuthority;
    
    IBOutlet UITextView* _resultView;
    
    IBOutlet UIView* _authView;
    IBOutlet UIWebView* _webView;
    
    BOOL _userIdEdited;
}

- (id)init
{
    if (!(self = [super initWithNibName:@"ADTestAppAcquireTokenView" bundle:nil]))
    {
        return nil;
    }
    
    UITabBarItem* tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Acquire" image:nil tag:0];
    [self setTabBarItem:tabBarItem];
    
    [self setEdgesForExtendedLayout:UIRectEdgeTop];
    
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    [self.view addSubview:_acquireSettingsView];
    [_authView setHidden:YES];
    [self.view addSubview:_authView];
    
    [_userIdField addTarget:self action:@selector(textFieldChanged:) forControlEvents:UIControlEventEditingChanged];
    
}

- (void)textFieldChanged:(id)sender
{
    _userIdEdited = ![NSString adIsStringNilOrBlank:_userIdField.text];
}

- (void)viewWillAppear:(BOOL)animated
{
    if (!_userIdEdited)
    {
        NSString* defaultUser = [[ADTestAppSettings settings] defaultUser];
        [_userIdField setText:defaultUser];
    }
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
    
    if ([userIdType isEqualToString:@"O"])
    {
        idType = OptionalDisplayableId;
    }
    else if ([userIdType isEqualToString:@"R"])
    {
        idType = RequiredDisplayableId;
    }
    else if ([userIdType isEqualToString:@"U"])
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
    NSString* credType = [_credentialsType titleForSegmentAtIndex:[_credentialsType selectedSegmentIndex]];
    
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
    
    if ([webViewType isEqualToString:@"ADAL UI"])
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

- (IBAction)acquireTokenPromptAlways:(id)sender
{
    [self acquireTokenInteractive:AD_PROMPT_ALWAYS];
}

- (IBAction)acquireTokenPromptAuto:(id)sender
{
    [self acquireTokenInteractive:AD_PROMPT_AUTO];
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

- (void)acquireTokenInteractive:(ADPromptBehavior)promptBehavior
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
                       promptBehavior:promptBehavior
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

@end
