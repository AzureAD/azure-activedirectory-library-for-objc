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

#import "ADTestAppAcquireTokenWindowController.h"
#import "ADAL_Internal.h"
#import "ADUserIdentifier.h"
#import "ADTestAppSettings.h"
#import "ADTokenCache.h"
#import "ADAuthenticationSettings.h"
#import "ADWebAuthController.h"
#import "ADTestAppCache.h"


@interface ADTestAppAcquireTokenWindowController ()

@end

@implementation ADTestAppAcquireTokenWindowController

+ (void)showWindow
{
    static ADTestAppAcquireTokenWindowController* controller = nil;
    
    static dispatch_once_t once;
    
    dispatch_once(&once, ^{
        controller = [[ADTestAppAcquireTokenWindowController alloc] init];
        
        
    });
    
    [controller showWindow:nil];
}

- (id)init
{
    if (!(self = [super initWithWindowNibName:@"AcquireTokenWindow"]))
    {
        return nil;
    }
    
    _idType = OptionalDisplayableId;
    _promptBehavior = AD_PROMPT_ALWAYS;
    
    return self;
}

- (void)populateProfiles
{
    [_profiles removeAllItems];
    [_profiles setTarget:self];
    [_profiles setAction:@selector(selectedProfileChanged:)];
    NSUInteger cProfiles = [ADTestAppSettings numberOfProfiles];
    for (NSUInteger i = 0; i < cProfiles; i++)
    {
        [_profiles addItemWithTitle:[ADTestAppSettings profileTitleForIndex:i]];
    }
    
    [_profiles selectItemAtIndex:[ADTestAppSettings currentProfileIdx]];
}

- (void)populateCurrentProfile
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    
    _authority.stringValue = settings.authority;
    _clientId.stringValue = settings.clientId;
    _redirectUri.stringValue = settings.redirectUri.absoluteString;
    _resource.stringValue = settings.resource;
    _userIdField.stringValue = settings.defaultUser ? settings.defaultUser : @"";
}

- (IBAction)selectedProfileChanged:(id)sender
{
    [[ADTestAppSettings settings] setProfileFromIndex:[_profiles indexOfSelectedItem]];
    [self populateCurrentProfile];
}

- (void)windowDidLoad
{
    [super windowDidLoad];
    
    [self.window.contentView addSubview:_acquireSettingsView];
    [_authView setHidden:YES];
    [self.window.contentView addSubview:_authView];
    
    [self populateProfiles];
    [self populateCurrentProfile];
}

- (IBAction)setIdentifierType:(id)sender
{
    NSButton* button = (NSButton*)sender;
    NSString* idType = button.title;
    
    if ([idType isEqualToString:@"OptionalDisplayableId"])
    {
        _idType = OptionalDisplayableId;
    }
    else if ([idType isEqualToString:@"RequiredDisplayableId"])
    {
        _idType = RequiredDisplayableId;
    }
    else if ([idType isEqualToString:@"UniqueId"])
    {
        _idType = UniqueId;
    }
    else
    {
        @throw @"Unrecognized ID type";
    }
}

- (IBAction)setPromptBehavior:(id)sender
{
    NSButton* button = (NSButton*)sender;
    NSString* prompt = button.title;
    
    if ([prompt isEqualToString:@"Auto"])
    {
        _promptBehavior = AD_PROMPT_AUTO;
    }
    else if ([prompt isEqualToString:@"Always"])
    {
        _promptBehavior = AD_PROMPT_ALWAYS;
    }
    else
    {
        @throw @"Unrecognized prompt behavior";
    }
}

- (void)textFieldChanged:(id)sender
{
    _userIdEdited = ![NSString adIsStringNilOrBlank:_userIdField.stringValue];
}

- (void)viewWillAppear:(BOOL)animated
{
    if (!_userIdEdited)
    {
        NSString* defaultUser = [[ADTestAppSettings settings] defaultUser];
        [_userIdField setStringValue:defaultUser];
    }
}

- (ADUserIdentifier*)identifier
{
    NSString* userId = [_userIdField stringValue];
    
    if (!userId || [userId isEqualToString:@""])
    {
        return nil;
    }
    
    return [ADUserIdentifier identifierWithId:userId type:_idType];
}

- (BOOL)embeddedWebView
{
    NSString* webViewType = [_webViewType labelForSegment:[_webViewType selectedSegment]];
    
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
    
    [_resultView setString:resultText];
    
    printf("%s", [resultText UTF8String]);
}

- (void)showMultipleHitAlert
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert* alert = [NSAlert alertWithMessageText:@"Error!"
                                         defaultButton:@"OK"
                                       alternateButton:nil
                                           otherButton:nil
                             informativeTextWithFormat:@"Completion block was hit multiple times!"];
        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode)
         {
             (void)returnCode;
         }];
    });
}

- (IBAction)acquireTokenInteractive:(id)sender
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    NSString* authority = [settings authority];
    NSString* resource = [settings resource];
    NSString* clientId = [settings clientId];
    NSURL* redirectUri = [settings redirectUri];
    ADUserIdentifier* identifier = [self identifier];
    
    BOOL validateAuthority = _validateAuthority.selectedSegment == 0;
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:validateAuthority
                                                                                    error:&error];
    if (!context)
    {
        NSString* resultText = [NSString stringWithFormat:@"Failed to create AuthenticationContext:\n%@", error];
        [_resultView setString:resultText];
        return;
    }
    
    if ([self embeddedWebView])
    {
        [_webView.mainFrame loadHTMLString:@"<html><head></head><body>Loading...</body></html>" baseURL:nil];
        [context setWebView:_webView];
        [_authView setFrame:self.window.contentView.frame];
        
        [_acquireSettingsView setHidden:YES];
        [_authView setHidden:NO];
    }
    
    __block BOOL fBlockHit = NO;
    
    [context acquireTokenWithResource:resource
                             clientId:clientId
                          redirectUri:redirectUri
                       promptBehavior:_promptBehavior
                       userIdentifier:identifier
                 extraQueryParameters:nil
                      completionBlock:^(ADAuthenticationResult *result)
     {
         if (fBlockHit)
         {
             [self showMultipleHitAlert];
             return;
         }
         fBlockHit = YES;
         
         
         
         dispatch_async(dispatch_get_main_queue(), ^{
             [self updateResultView:result];
             
             if ([_acquireSettingsView isHidden])
             {
                 [_webView.mainFrame loadHTMLString:@"<html><head></head><body>done!</body></html>" baseURL:nil];
                 [_authView setHidden:YES];
                 [_acquireSettingsView setHidden:NO];
             }
             
             [[NSNotificationCenter defaultCenter] postNotificationName:ADTestAppCacheChangeNotification object:self];
         });
     }];
    
}

- (IBAction)cancelAuth:(id)sender
{
    [ADWebAuthController cancelCurrentWebAuthSession];
}

- (IBAction)clearCache:(id)sender
{
    NSError* error = nil;
    BOOL result = [[ADTestAppCache sharedCache] clearCacheWithError:&error];
    
    if (result)
    {
        _resultView.string = @"Successfully cleared cache.";
    }
    else
    {
        _resultView.string = [NSString stringWithFormat:@"Failed to clear cache, error = %@", error];
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
    
    [_resultView setString:[NSString stringWithFormat:@"Cleared %lu cookies.", (unsigned long)cookies.count]];
}

- (IBAction)acquireTokenSilent:(id)sender
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    NSString* authority = [settings authority];
    NSString* resource = [settings resource];
    NSString* clientId = [settings clientId];
    NSURL* redirectUri = [settings redirectUri];
    ADUserIdentifier* identifier = [self identifier];
    BOOL validateAuthority = _validateAuthority.selectedSegment == 0;
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority validateAuthority:validateAuthority error:&error];
    if (!context)
    {
        NSString* resultText = [NSString stringWithFormat:@"Failed to create AuthenticationContext:\n%@", error];
        [_resultView setString:resultText];
        return;
    }
    
    __block BOOL fBlockHit = NO;
    
    [context acquireTokenSilentWithResource:resource clientId:clientId redirectUri:redirectUri userId:identifier.userId completionBlock:^(ADAuthenticationResult *result)
     {
         if (fBlockHit)
         {
             [self showMultipleHitAlert];
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
