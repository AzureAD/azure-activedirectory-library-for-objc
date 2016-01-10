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
#import "ADALiOS.h"
#import "ADURLProtocol.h"
#import "UIAlertView+Additions.h"

static NSString* const AD_WPJ_LOG = @"ADNTLMHandler";
@implementation ADNTLMHandler

static NSString *_username = nil;
static NSString *_password = nil;
static NSString *_cancellationUrl = nil;
static BOOL _challengeCancelled = NO;
static NSMutableURLRequest *_challengeUrl = nil;
static NSURLConnection *_conn = nil;

+ (void)load
{
    [ADURLProtocol registerHandler:self
                        authMethod:NSURLAuthenticationMethodNTLM];
}

+ (void)setCancellationUrl:(NSString*) url
{
    _cancellationUrl = url;
}

+ (BOOL)isChallengeCancelled
{
    return _challengeCancelled;
}

/* Stops the HTTPS interception. */
+ (void)resetHandler
{
    @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
    {
        _username = nil;
        _password = nil;
        _challengeUrl = nil;
        _cancellationUrl = nil;
        _conn = nil;
        _challengeCancelled = NO;
        AD_LOG_VERBOSE(AD_WPJ_LOG, nil, @"NTLM session ended");
    }
}

+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge *)challenge
             connection:(NSURLConnection*)connection
               protocol:(ADURLProtocol*)protocol
{
    (void)connection;
    BOOL __block succeeded = NO;
    @synchronized(self)
    {
        if(_conn){
            _conn = nil;
        }
        // This is the NTLM challenge: use the identity to authenticate:
        AD_LOG_VERBOSE_F(AD_WPJ_LOG, nil, @"Attempting to handle NTLM challenge for host: %@", challenge.protectionSpace.host);
        [UIAlertView presentCredentialAlert:^(NSUInteger index) {
            if (index == 1)
            {
                UITextField *username = [[UIAlertView getAlertInstance] textFieldAtIndex:0];
                _username = username.text;
                UITextField *password = [[UIAlertView getAlertInstance] textFieldAtIndex:1];
                _password = password.text;
                
                NSURLCredential *credential;
                credential = [NSURLCredential
                              credentialWithUser:_username
                              password:_password
                              persistence:NSURLCredentialPersistenceForSession];
                [challenge.sender useCredential:credential
                     forAuthenticationChallenge:challenge];
            } else {
                _challengeCancelled = YES;
                [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
                [protocol stopLoading];
            }
        }];
        succeeded = YES;
    }//@synchronized
    
    return succeeded;
}

@end
