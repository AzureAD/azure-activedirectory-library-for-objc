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

#import "ADAuthenticationContext+Internal.h"
#import "ADWebRequest.h"
#import "ADWorkPlaceJoinConstants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADClientMetrics.h"
#import "ADWebResponse.h"
#import "ADPkeyAuthHelper.h"
#import "ADAuthenticationSettings.h"
#import "ADWebAuthController.h"
#import "ADWebAuthController+Internal.h"
#import "ADHelpers.h"
#import "NSURL+ADExtensions.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADWebAuthRequest.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryUIEvent.h"

#import <libkern/OSAtomic.h>

static ADAuthenticationRequest* s_modalRequest = nil;

@implementation ADAuthenticationRequest (WebRequest)

+ (ADAuthenticationRequest*)currentModalRequest
{
    return s_modalRequest;
}

- (void)executeRequest:(NSDictionary *)request_data
            completion:(ADAuthenticationCallback)completionBlock
{
    NSString* urlString = [_context.authority stringByAppendingString:OAUTH2_TOKEN_SUFFIX];
    ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                                    requestParams:_requestParams];
    [req setRequestDictionary:request_data];
    [req sendRequest:^(NSDictionary *response)
     {
         //Prefill the known elements in the item. These can be overridden by the response:
         ADTokenCacheItem* item = [ADTokenCacheItem new];
         item.resource = [_requestParams resource];
         item.clientId = [_requestParams clientId];
         item.authority = _context.authority;
         ADAuthenticationResult* result = [item processTokenResponse:response
                                                         fromRefresh:NO
                                                requestCorrelationId:[_requestParams correlationId]];
         SAFE_ARC_RELEASE(item);
         completionBlock(result);
     }];
}

//Ensures that a single UI login dialog can be requested at a time.
//Returns true if successfully acquired the lock. If not, calls the callback with
//the error and returns false.
- (BOOL)takeExclusionLockWithCallback: (ADAuthorizationCodeCallback) completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    if ( ![self takeUserInterationLock] )
    {
        NSString* message = @"The user is currently prompted for credentials as result of another acquireToken request. Please retry the acquireToken call later.";
        ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS
                                                                              protocolCode:nil
                                                                              errorDetails:message
                                                                             correlationId:[_requestParams correlationId]];
        completionBlock(nil, error);
        return NO;
    }
    
    s_modalRequest = self;
    return YES;
}

//Attempts to release the lock. Logs warning if the lock was already released.
-(void) releaseExclusionLock
{
    [self releaseUserInterationLock];
    s_modalRequest = nil;
}

//Ensures that the state comes back in the response:
- (BOOL)verifyStateFromDictionary: (NSDictionary*) dictionary
{
    NSDictionary *state = [NSDictionary adURLFormDecode:[[dictionary objectForKey:OAUTH2_STATE] adBase64UrlDecode]];
    if (state.count != 0)
    {
        NSString *authorizationServer = [state objectForKey:@"a"];
        NSString *resource            = [state objectForKey:@"r"];
        
        if (![NSString adIsStringNilOrBlank:authorizationServer] && ![NSString adIsStringNilOrBlank:resource])
        {
            AD_LOG_VERBOSE_F(@"State", [_requestParams correlationId], @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    AD_LOG_WARN_F(@"State error", [_requestParams correlationId], @"Missing or invalid state returned: %@", state);
    return NO;
}

// Encodes the state parameter for a protocol message
- (NSString *)encodeProtocolState
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:[_requestParams authority], @"a", [_requestParams resource], @"r", _scope, @"s", nil]
             adURLFormEncode] adBase64UrlEncode];
}

//Generates the query string, encoding the state:
- (NSString*)generateQueryStringForRequestType:(NSString*)requestType
{
    NSString* state = [self encodeProtocolState];
    NSString* queryParams = nil;
    // Start the web navigation process for the Implicit grant profile.
    NSMutableString* startUrl = [NSMutableString stringWithFormat:@"%@?%@=%@&%@=%@&%@=%@&%@=%@&%@=%@",
                                 [_context.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX],
                                 OAUTH2_RESPONSE_TYPE, requestType,
                                 OAUTH2_CLIENT_ID, [[_requestParams clientId] adUrlFormEncode],
                                 OAUTH2_RESOURCE, [[_requestParams resource] adUrlFormEncode],
                                 OAUTH2_REDIRECT_URI, [[_requestParams redirectUri] adUrlFormEncode],
                                 OAUTH2_STATE, state];
    
    [startUrl appendFormat:@"&%@", [[ADLogger adalId] adURLFormEncode]];
    
    if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
    {
        [startUrl appendFormat:@"&%@=%@", OAUTH2_LOGIN_HINT, [[_requestParams identifier].userId adUrlFormEncode]];
    }
    NSString* promptParam = [ADAuthenticationContext getPromptParameter:_promptBehavior];
    if (promptParam)
    {
        //Force the server to ignore cookies, by specifying explicitly the prompt behavior:
        [startUrl appendString:[NSString stringWithFormat:@"&prompt=%@", promptParam]];
    }
    
    [startUrl appendString:@"&haschrome=1"]; //to hide back button in UI
    
    if (![NSString adIsStringNilOrBlank:_queryParams])
    {//Append the additional query parameters if specified:
        queryParams = _queryParams.adTrimmedString;
        
        //Add the '&' for the additional params if not there already:
        if ([queryParams hasPrefix:@"&"])
        {
            [startUrl appendString:queryParams];
        }
        else
        {
            [startUrl appendFormat:@"&%@", queryParams];
        }
    }
    
    return startUrl;
}

- (void)launchWebView:(NSString*)startUrl
      completionBlock:(void (^)(ADAuthenticationError*, NSURL*))completionBlock
{
    [[ADTelemetry sharedInstance] startEvent:[self telemetryRequestId] eventName:@"launch_web_view"];
    void(^requestCompletion)(ADAuthenticationError *error, NSURL *end) = ^void(ADAuthenticationError *error, NSURL *end)
    {
        ADTelemetryUIEvent* event = [[ADTelemetryUIEvent alloc] initWithName:@"launch_web_view"
                                                                   requestId:[self telemetryRequestId]
                                                               correlationId:[self correlationId]];
        [self fillTelemetryUIEvent:event];
        [[ADTelemetry sharedInstance] stopEvent:[self telemetryRequestId] event:event];
        
        completionBlock(error, end);
    };
    
    [[ADWebAuthController sharedInstance] start:[NSURL URLWithString:startUrl]
                                            end:[NSURL URLWithString:[_requestParams redirectUri]]
                                    refreshCred:_refreshTokenCredential
#if TARGET_OS_IPHONE
                                         parent:_context.parentController
                                     fullScreen:[ADAuthenticationSettings sharedInstance].enableFullScreen
#endif
                                        webView:_context.webView
                                  correlationId:[_requestParams correlationId]
                                     completion:requestCompletion];
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    AD_LOG_VERBOSE_F(@"Requesting authorization code.", [_requestParams correlationId], @"Requesting authorization code for resource: %@", [_requestParams resource]);
    if (![self takeExclusionLockWithCallback:completionBlock])
    {
        return;
    }
    
    NSString* startUrl = [self generateQueryStringForRequestType:OAUTH2_CODE];
    
    void(^requestCompletion)(ADAuthenticationError *error, NSURL *end) = ^void(ADAuthenticationError *error, NSURL *end)
    {
        [self releaseExclusionLock]; // Allow other operations that use the UI for credentials.
         
         NSString* code = nil;
         if (!error)
         {
             
             if ([[[end scheme] lowercaseString] isEqualToString:@"msauth"]) {
#if AD_BROKER
                 
                 NSString* host = [end host];
                 if ([host isEqualToString:@"microsoft.aad.brokerplugin"] || [host isEqualToString:@"code"])
                 {
                     NSDictionary* queryParams = [end adQueryParameters];
                     code = [queryParams objectForKey:OAUTH2_CODE];
                 }
                 else
                 {
                     NSDictionary* userInfo = @{
                                                @"username": [[NSDictionary adURLFormDecode:[end query]] valueForKey:@"username"],
                                                };
                     NSError* err = [NSError errorWithDomain:ADAuthenticationErrorDomain
                                                        code:AD_ERROR_SERVER_WPJ_REQUIRED
                                                    userInfo:userInfo];
                     error = [ADAuthenticationError errorFromNSError:err errorDetails:@"work place join is required"];
                 }
#else
                 code = end.absoluteString;
#endif
             }
             else
             {
                 //Try both the URL and the fragment parameters:
                 NSDictionary *parameters = [end adFragmentParameters];
                 if ( parameters.count == 0 )
                 {
                     parameters = [end adQueryParameters];
                 }
                 
                 //OAuth2 error may be passed by the server:
                 error = [ADAuthenticationContext errorFromDictionary:parameters errorCode:AD_ERROR_SERVER_AUTHORIZATION_CODE];
                 if (!error)
                 {
                     //Note that we do not enforce the state, just log it:
                     [self verifyStateFromDictionary:parameters];
                     code = [parameters objectForKey:OAUTH2_CODE];
                     if ([NSString adIsStringNilOrBlank:code])
                     {
                         error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_AUTHORIZATION_CODE
                                                                        protocolCode:nil
                                                                        errorDetails:@"The authorization server did not return a valid authorization code."
                                                                       correlationId:[_requestParams correlationId]];
                     }
                 }
             }
         }
         
         completionBlock(code, error);
     };
    
    // If this request doesn't allow us to attempt to grab a code silently (using
    // a potential SSO cookie) then jump straight to the web view.
    if (!_allowSilent)
    {
        [self launchWebView:startUrl
            completionBlock:requestCompletion];
    }
    else
    {
        NSMutableDictionary* requestData = nil;
        requestData = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                       [_requestParams clientId], OAUTH2_CLIENT_ID,
                       [_requestParams redirectUri], OAUTH2_REDIRECT_URI,
                       [_requestParams resource], OAUTH2_RESOURCE,
                       OAUTH2_CODE, OAUTH2_RESPONSE_TYPE,
					   @"1", @"nux", nil];
        
        if (_scope)
        {
            [requestData setObject:_scope forKey:OAUTH2_SCOPE];
        }
        
        NSURL* reqURL = [NSURL URLWithString:[_context.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX]];
        ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:reqURL
                                                        requestParams:_requestParams];
        [req setIsGetRequest:YES];
        [req setRequestDictionary:requestData];
        [req sendRequest:^(NSDictionary * parameters)
         {
             
             NSURL* endURL = nil;
             ADAuthenticationError* error = nil;
             
             //OAuth2 error may be passed by the server
             endURL = [parameters objectForKey:@"url"];
             if (!endURL)
             {
                 // If the request was not silent only then launch the webview
                 if (!_silent)
                 {
                     [self launchWebView:startUrl
                         completionBlock:requestCompletion];
                     return;
                 }
                 
                 // Otherwise error out
                 error = [ADAuthenticationContext errorFromDictionary:parameters errorCode:AD_ERROR_SERVER_AUTHORIZATION_CODE];
             }
             
             requestCompletion(error, endURL);
         }];
    }
}

- (void)fillTelemetryUIEvent:(ADTelemetryUIEvent*)event
{
    if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
    {
        [event setLoginHint:[_requestParams identifier].userId];
    }
}

@end
