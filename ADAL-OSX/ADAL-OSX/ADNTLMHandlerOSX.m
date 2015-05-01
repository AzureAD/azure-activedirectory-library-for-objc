// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADNTLMHandler.h"
#import "ADAuthenticationSettings.h"
#import "NSString+ADHelperMethods.h"
#import "ADErrorCodes.h"
#import "ADKeyChainHelper.h"
#import "ADURLProtocol.h"
#import "ADCredentialCollectionController.h"

NSString* const AD_WPJ_LOG = @"ADNTLMHandler";

@interface NTLMSheetHelper : NSObject
{
    dispatch_semaphore_t _dsem;
    NSAlert*            _alert;
    NSModalResponse     _response;
    NSString*           _username;
    NSString*           _password;
}

@property (readwrite, retain) NSString* username;
@property (readwrite, retain) NSString* password;


- (id)init;
- (NSModalResponse)showNTLMSheet;

@end

@implementation NTLMSheetHelper

@synthesize username = _username;
@synthesize password = _password;

- (id)init
{
    if (!(self = [super init]))
        return nil;
    
    _dsem = dispatch_semaphore_create(0);

    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_alert);
    dispatch_release(_dsem);
    SAFE_ARC_SUPER_DEALLOC();
}

- (void)internalShowNTLMSheet
{
    _alert = [NSAlert alertWithMessageText:NSLocalizedString(@"Enter your credentials", nil)
                             defaultButton:NSLocalizedString(@"Login", nil)
                           alternateButton:NSLocalizedString(@"Cancel", nil)
                               otherButton:nil
                 informativeTextWithFormat:@""];
    
    SAFE_ARC_RETAIN(_alert);
    
    ADCredentialCollectionController *view = [ADCredentialCollectionController new];
    [view.usernameLabel setStringValue:NSLocalizedString(@"User Name", nil)];
    [view.passwordLabel setStringValue:NSLocalizedString(@"Password", nil)];
    [_alert setAccessoryView:view.customView];
    
    [_alert beginSheetModalForWindow:[NSApp keyWindow] completionHandler:^(NSModalResponse returnCode) {
        _response = returnCode;
        
        _username = [view.usernameField stringValue];
        _password = [view.passwordField stringValue];
        dispatch_semaphore_signal(_dsem);
    }];
}

- (NSModalResponse)showNTLMSheet
{
    [self performSelectorOnMainThread:@selector(internalShowNTLMSheet) withObject:nil waitUntilDone:NO modes:[NSArray arrayWithObject:NSRunLoopCommonModes]];
    dispatch_semaphore_wait(_dsem, DISPATCH_TIME_FOREVER);
    return _response;
}


@end

@implementation ADNTLMHandler

BOOL _challengeCancelled = NO;
NSMutableURLRequest *_challengeUrl = nil;
NSURLConnection *_conn = nil;

+(BOOL) isChallengeCancelled
{
    return _challengeCancelled;
}

+(BOOL) startWebViewNTLMHandlerWithError: (ADAuthenticationError *__autoreleasing *) error
{
    @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
    {
        AD_LOG_VERBOSE(AD_WPJ_LOG, @"Attempting to start the NTLM session for webview.");
        
        BOOL succeeded = NO;
        if ([NSURLProtocol registerClass:[ADURLProtocol class]])
        {
            succeeded = YES;
            AD_LOG_VERBOSE(AD_WPJ_LOG, @"NTLM session started.");
        }
        else
        {
            ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Failed to register NSURLProtocol."];
            if (error)
            {
                *error = adError;
            }
        }
        return succeeded;
    }
}

/* Stops the HTTPS interception. */
+(void) endWebViewNTLMHandler
{
    @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
    {
        [NSURLProtocol unregisterClass:[ADURLProtocol class]];
        _challengeUrl = nil;
        _conn = nil;
        _challengeCancelled = NO;
        AD_LOG_VERBOSE(AD_WPJ_LOG, @"NTLM session ended");
    }
}

+(BOOL) handleNTLMChallenge:(NSURLAuthenticationChallenge *)challenge
             customProtocol:(NSURLProtocol*) protocol
{
    
    BOOL __block succeeded = NO;
    AD_LOG_VERBOSE_F(AD_WPJ_LOG, @"Challenge Type for host: %@", challenge.protectionSpace.authenticationMethod);
    
    if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodNegotiate] == NSOrderedSame)
    {
        [challenge.sender rejectProtectionSpaceAndContinueWithChallenge:challenge];
        return YES;
    }
    
    if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodNTLM] == NSOrderedSame)
    {
        @synchronized(self)
        {
            if(_conn){
                _conn = nil;
            }
            
            AD_LOG_VERBOSE_F(AD_WPJ_LOG, @"Attempting to handle %@ challenge for host: %@", challenge.protectionSpace.authenticationMethod, challenge.protectionSpace.host);
            
            NTLMSheetHelper* helper = [NTLMSheetHelper new];
            NSModalResponse returnCode = [helper showNTLMSheet];
            
            if (returnCode == 1){
                NSURLCredential *credential;
                credential = [NSURLCredential
                              credentialWithUser:helper.username
                              password:helper.password
                              persistence:NSURLCredentialPersistenceForSession];
                [challenge.sender useCredential:credential
                     forAuthenticationChallenge:challenge];
                AD_LOG_VERBOSE(AD_WPJ_LOG, @"NTLM challenge responded.");
                _challengeUrl = nil;
            } else if (returnCode == 0) {
                _challengeCancelled = YES;
                [protocol stopLoading];
            }
            SAFE_ARC_RELEASE(helper);
            
            succeeded = YES;
            
        }//@synchronized
    }//Challenge type
    
    return succeeded;
}

@end
