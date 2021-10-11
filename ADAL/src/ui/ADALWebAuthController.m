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

#import "ADALWebAuthController+Internal.h"
#import "ADALUserIdentifier.h"
#import "ADALAuthenticationContext+Internal.h"
#import "MSIDNotifications.h"
#import "NSDictionary+MSIDExtensions.h"
#import "ADALAuthenticationSettings.h"
#import "MSIDTelemetry+Internal.h"
#import "MSIDTelemetryUIEvent.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADALAuthorityUtils.h"
#import "MSIDAadAuthorityCache.h"
#import "MSIDAuthorityFactory.h"
#import "MSIDAuthority.h"
#import "MSIDAADAuthority.h"
#import "MSIDClientCapabilitiesUtil.h"
#import "MSIDAADEndpointProvider.h"

/*! Fired at the start of a resource load in the webview. */
NSString* ADWebAuthDidStartLoadNotification = @"ADWebAuthDidStartLoadNotification";

/*! Fired when a resource finishes loading in the webview. */
NSString* ADWebAuthDidFinishLoadNotification = @"ADWebAuthDidFinishLoadNotification";

/*! Fired when web authentication fails due to reasons originating from the network. */
NSString* ADWebAuthDidFailNotification = @"ADWebAuthDidFailNotification";

/*! Fired when authentication finishes */
NSString* ADWebAuthDidCompleteNotification = @"ADWebAuthDidCompleteNotification";

NSString* ADWebAuthDidReceieveResponseFromBroker = @"ADWebAuthDidReceiveResponseFromBroker";

NSString* ADWebAuthWillSwitchToBrokerApp = @"ADWebAuthWillSwitchToBrokerApp";

NSString* ADWebAuthIgnoreSSOHeader = @"x-ms-sso-Ignore-SSO";

NSString* ADWebAuthRefreshTokenHeader = @"x-ms-sso-RefreshToken";

// Private interface declaration
@interface ADALWebAuthController ()
@end

// Implementation
@implementation ADALWebAuthController

#pragma mark - Initialization

+ (void)cancelCurrentWebAuthSession
{
    [MSIDWebviewAuthorization cancelCurrentSession];
}

#if TARGET_OS_IPHONE
static ADALAuthenticationResult *s_result = nil;

+ (ADALAuthenticationResult *)responseFromInterruptedBrokerSession
{
    ADALAuthenticationResult *result = s_result;
    s_result = nil;
    return result;
}
#endif // TARGET_OS_IPHONE
@end

#pragma mark - Private Methods

@implementation ADALWebAuthController (Internal)

+ (void)registerWebAuthNotifications
{
    MSIDNotifications.webAuthDidCompleteNotificationName = ADWebAuthDidCompleteNotification;
    MSIDNotifications.webAuthDidFailNotificationName = ADWebAuthDidFailNotification;
    MSIDNotifications.webAuthDidStartLoadNotificationName = ADWebAuthDidStartLoadNotification;
    MSIDNotifications.webAuthDidFinishLoadNotificationName = ADWebAuthDidFinishLoadNotification;
}

+ (void)startWithRequest:(ADALRequestParameters *)requestParams
          promptBehavior:(ADALPromptBehavior)promptBehavior
            refreshToken:(NSString*)refreshToken
                 context:(ADALAuthenticationContext *)context
              completion:(MSIDWebviewAuthCompletionHandler)completionHandler
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [self registerWebAuthNotifications];
    });

    NSURL *requestAuthorityURL = [NSURL URLWithString:context.authority];

    MSIDAADAuthority *aadAuthority = [[MSIDAADAuthority alloc] initWithURL:requestAuthorityURL context:nil error:nil];

    if (aadAuthority)
    {
        requestAuthorityURL = [aadAuthority networkUrlWithContext:nil];
    }

    NSURL *authorityURLWithOauthSuffix = [[MSIDAADEndpointProvider new] oauth2AuthorizeEndpointWithUrl:requestAuthorityURL];
    
    MSIDWebviewConfiguration *webviewConfig = [[MSIDWebviewConfiguration alloc] initWithAuthorizationEndpoint:authorityURLWithOauthSuffix
                                                                                                  redirectUri:requestParams.redirectUri
                                                                                                     clientId:requestParams.clientId
                                                                                                     resource:requestParams.resource
                                                                                                       scopes:nil
                                                                                                correlationId:requestParams.correlationId
                                                                                                   enablePkce:NO];
    webviewConfig.ignoreInvalidState = YES;

    webviewConfig.loginHint = requestParams.identifier.userId;
    webviewConfig.promptBehavior = [ADALAuthenticationContext getPromptParameter:promptBehavior];
    
    webviewConfig.extraQueryParameters = [self.class dictionaryFromQueryString:requestParams.extraQueryParameters.msidWWWFormURLDecode];

    NSString *claims = [MSIDClientCapabilitiesUtil msidClaimsParameterFromCapabilities:requestParams.clientCapabilities developerClaims:requestParams.decodedClaims];
    
    if (![NSString msidIsStringNilOrBlank:claims])
    {
        webviewConfig.claims = [claims msidWWWFormURLDecode];
    }

#if TARGET_OS_IPHONE
    webviewConfig.parentController = context.parentController;
    webviewConfig.presentationType = ADALAuthenticationSettings.sharedInstance.webviewPresentationStyle;
#endif

    if ([context useRefreshTokenForWebview])
    {
        [[webviewConfig customHeaders] setObject:@"1" forKey:ADWebAuthIgnoreSSOHeader];
        if (![NSString msidIsStringNilOrBlank:refreshToken])
        {
            [[webviewConfig customHeaders] setObject:refreshToken forKey:ADWebAuthRefreshTokenHeader];
        }
    }

    [MSIDWebviewAuthorization startEmbeddedWebviewAuthWithConfiguration:webviewConfig
                                                          oauth2Factory:context.oauthFactory
                                                                webview:context.webView
                                                                context:requestParams
                                                      completionHandler:completionHandler];
}

//TODO: Replace with MSID utility
+ (NSDictionary *)dictionaryFromQueryString:(NSString *)string
{
    if ([NSString msidIsStringNilOrBlank:string])
    {
        return nil;
    }
    
    NSArray *queries = [string componentsSeparatedByString:@"&"];
    NSMutableDictionary *queryDict = [NSMutableDictionary new];
    
    for (NSString *query in queries)
    {
        NSArray *queryElements = [query componentsSeparatedByString:@"="];
        if (queryElements.count > 2)
        {
            MSID_LOG_WARN(nil, @"Query parameter must be a form key=value: %@", query);
            continue;
        }
        
        NSString *key = [queryElements[0] msidTrimmedString];
        if ([NSString msidIsStringNilOrBlank:key])
        {
            MSID_LOG_WARN(nil, @"Query parameter must have a key");
            continue;
        }
        
        NSString *value = @"";
        if (queryElements.count == 2)
        {
            value = [queryElements[1] msidTrimmedString];
        }
        
        [queryDict setValue:value forKey:key];
    }
    
    return queryDict;
}


#if TARGET_OS_IPHONE
+ (void)setInterruptedBrokerResult:(ADALAuthenticationResult *)result
{
    s_result = result;
}
#endif // TARGET_OS_IPHONE

@end
