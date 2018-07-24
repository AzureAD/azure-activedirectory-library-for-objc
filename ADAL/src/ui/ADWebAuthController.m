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

#if TARGET_OS_IPHONE
#import "UIApplication+ADExtensions.h"
#import "ADAppExtensionUtil.h"
#endif

#import "ADWebAuthController+Internal.h"

#import "ADAuthenticationViewController.h"
#import "ADAuthenticationSettings.h"
#import "ADAuthorityValidation.h"
#import "ADCustomHeaderHandler.h"
#import "ADHelpers.h"
#import "ADNTLMHandler.h"
#import "ADPkeyAuthHelper.h"
#import "ADURLProtocol.h"
#import "ADWebAuthDelegate.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADUserIdentifier.h"
#import "ADTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "MSIDTelemetryUIEvent.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADAuthorityUtils.h"
#import "MSIDAadAuthorityCache.h"

#import "MSIDWebviewAuthorization.h"
#import "ADMSIDContext.h"
#import "MSIDAADV1WebviewFactory.h"

#import "ADAuthenticationContext+Internal.h"

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

// Private interface declaration
@interface ADWebAuthController ()
@end

// Implementation
@implementation ADWebAuthController

#pragma mark - Initialization

+ (void)cancelCurrentWebAuthSession
{
    [MSIDWebviewAuthorization cancelCurrentSession];
}

#if TARGET_OS_IPHONE
static ADAuthenticationResult *s_result = nil;

+ (ADAuthenticationResult *)responseFromInterruptedBrokerSession
{
    ADAuthenticationResult *result = s_result;
    s_result = nil;
    return result;
}
#endif // TARGET_OS_IPHONE
@end

#pragma mark - Private Methods

@implementation ADWebAuthController (Internal)

+ (void)startWithRequest:(ADRequestParameters *)requestParams
          promptBehavior:(ADPromptBehavior)promptBehavior
                 context:(ADAuthenticationContext *)context
              completion:(ADAuthorizationCodeCallback)completionBlock
{
    NSString *authorityWithOAuthSuffix = [NSString stringWithFormat:@"%@%@", context.authority, MSID_OAUTH2_AUTHORIZE_SUFFIX];
    
    MSIDWebviewConfiguration *webviewConfig = [[MSIDWebviewConfiguration alloc] initWithAuthorizationEndpoint:[NSURL URLWithString:authorityWithOAuthSuffix]
                                                                                                  redirectUri:requestParams.redirectUri
                                                                                                     clientId:requestParams.clientId
                                                                                                     resource:requestParams.resource
                                                                                                       scopes:nil
                                                                                                correlationId:context.correlationId
                                                                                                   enablePkce:YES];
    webviewConfig.loginHint = requestParams.identifier.userId;
    webviewConfig.promptBehavior = [ADAuthenticationContext getPromptParameter:promptBehavior];
    
#if TARGET_OS_IPHONE
    webviewConfig.parentController = context.parentController;
#endif

    [MSIDWebviewAuthorization startEmbeddedWebviewAuthWithConfiguration:webviewConfig
                                                          oauth2Factory:context.oauthFactory
                                                                webview:context.webView
                                                                context:requestParams
                                                      completionHandler:^(MSIDWebviewResponse *response, NSError *error)
    {

                                                          
    
    }];
}

- (void)cancelCurrentWebAuthSession
{
    [MSIDWebviewAuthorization cancelCurrentSession];
}

/*
 
 
 config.promptBehavior = [ADAuthenticationContext getPromptParameter:_promptBehavior];
 //    config.loginHint = _requestParams.identifier.userId;
 //    config.parentController = _context.parentController;
 




 NSString *authorityWithOAuthSuffix = [NSString stringWithFormat:@"%@%@", _context.authority, MSID_OAUTH2_AUTHORIZE_SUFFIX];

 
 [ADWebAuthController startWithAuthorizationEndpoint:[NSURL URLWithString:authorityWithOAuthSuffix]
 redirectUri:_requestParams.redirectUri
 clientId:_requestParams.redirectUri
 resource:_requestParams.resource
 promptBehavior:[ADAuthenticationContext getPromptParameter:_promptBehavior]
 loginHint:_requestParams.identifier.userId
 context:_context
 completion:completionBlock];
 
 */


//
//+ (void)startWithWebviewConfig:(MSIDWebviewConfiguration *)configuration
//                       webView:(WKWebView *)webView
//                    completion:(MSIDWebviewAuthCompletionHandler)completionBlock
//{
//    (void)configuration;
//    (void)webView;
//    (void)completionBlock;
//    
//    [MSIDWebviewAuthorization startEmbeddedWebviewAuthWithConfiguration:configuration
//                                                          oauth2Factory:[MSIDAADV1Oauth2Factory new]
//                                                                webview:webView
//                                                                context:[[ADMSIDContext alloc] initWithCorrelationId:configuration.correlationId]
//                                                      completionHandler:^(MSIDWebviewResponse *response, NSError *error)
//    {
//        if ([response isKindOfClass:MSIDWebOAuth2Response.class])
//        {
////            MSIDWebOAuth2Response *oauthResponse = (MSIDWebOAuth2Response *)response;
////            _code = oauthResponse.authorizationCode;
//        }
//        /*
//         if ([response isKindOfClass:MSIDWebOAuth2Response.class])
//         {
//         MSIDWebOAuth2Response *oauthResponse = (MSIDWebOAuth2Response *)response;
//         _code = oauthResponse.authorizationCode;
//         
//         if ([response isKindOfClass:MSIDWebAADAuthResponse.class])
//         {
//         _cloudAuthority = [NSURL URLWithString:((MSIDWebAADAuthResponse *)response).cloudHostName];
//         }
//         
//         [super acquireToken:completionBlock];
//         return;
//         }
//         
//         
//         completionBlock(nil, error);
//         */
//        
//    }];
//}

//
//- (void)start:(NSURL *)startURL
//          end:(NSURL *)endURL
//  refreshCred:(NSString *)refreshCred
//#if TARGET_OS_IPHONE
//       parent:(UIViewController *)parent
//   fullScreen:(BOOL)fullScreen
//#endif
//      webView:(WebViewType *)webView
//      context:(ADRequestParameters*)requestParams
//   completion:(ADBrokerCallback)completionBlock
//{
//    THROW_ON_NIL_ARGUMENT(startURL);
//    THROW_ON_NIL_ARGUMENT(endURL);
//    THROW_ON_NIL_ARGUMENT(requestParams.correlationId);
//    THROW_ON_NIL_ARGUMENT(completionBlock);
//
//    // If we're not on the main thread when trying to kick up the UI then
//    // dispatch over to the main thread.
//    if (![NSThread isMainThread])
//    {
//        dispatch_async(dispatch_get_main_queue(), ^{
//            [self start:startURL
//                    end:endURL
//            refreshCred:refreshCred
//#if TARGET_OS_IPHONE
//                 parent:parent
//             fullScreen:fullScreen
//#endif
//                webView:webView
//                context:requestParams
//             completion:completionBlock];
//        });
//        return;
//    }
//
//    [[MSIDTelemetry sharedInstance] startEvent:requestParams.telemetryRequestId eventName:MSID_TELEMETRY_EVENT_UI_EVENT];
//    _telemetryEvent = [[MSIDTelemetryUIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_UI_EVENT
//                                                                 context:_requestParams];
//
//    startURL = [[MSIDAadAuthorityCache sharedInstance] networkUrlForAuthority:startURL context:requestParams];
//    startURL = [self addToURL:startURL correlationId:requestParams.correlationId];//Append the correlation id
//    _endURL = [endURL absoluteString];
//    _complete = NO;
//
//    _requestParams = requestParams;
//
//    // Save the completion block
//    _completionBlock = [completionBlock copy];
//    ADAuthenticationError* error = nil;
//
//    [ADURLProtocol registerProtocol:[endURL absoluteString] telemetryEvent:_telemetryEvent];
//
//    if(![NSString msidIsStringNilOrBlank:refreshCred])
//    {
//        [ADCustomHeaderHandler addCustomHeaderValue:refreshCred
//                                       forHeaderKey:@"x-ms-RefreshTokenCredential"
//                                       forSingleUse:YES];
//    }
//
//    _authenticationViewController = [[ADAuthenticationViewController alloc] init];
//    [_authenticationViewController setDelegate:self];
//    [_authenticationViewController setWebView:webView];
//#if TARGET_OS_IPHONE
//    [_authenticationViewController setParentController:parent];
//    [_authenticationViewController setFullScreen:fullScreen];
//#endif
//
//    if (![_authenticationViewController loadView:&error])
//    {
//        _completionBlock(error, nil);
//    }
//
//    NSMutableURLRequest* request = [[NSMutableURLRequest alloc] initWithURL:[ADHelpers addClientVersionToURL:startURL]];
//
//    [ADURLProtocol addContext:_requestParams toRequest:request];
//
//    [_authenticationViewController startRequest:request];
//}

#if TARGET_OS_IPHONE
+ (void)setInterruptedBrokerResult:(ADAuthenticationResult *)result
{
    s_result = result;
}
#endif // TARGET_OS_IPHONE

@end
