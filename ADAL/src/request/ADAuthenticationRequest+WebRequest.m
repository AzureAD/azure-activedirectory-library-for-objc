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
#import "NSString+ADURLExtensions.h"
#import "ADClientCapabilitiesUtil.h"

#import <libkern/OSAtomic.h>

@implementation ADAuthenticationRequest (WebRequest)

- (void)executeRequest:(NSDictionary *)request_data
            completion:(ADAuthenticationCallback)completionBlock
{
    NSString *authority = [NSString adIsStringNilOrBlank:_cloudAuthority] ? _context.authority : _cloudAuthority;
    NSString* urlString = [authority stringByAppendingString:OAUTH2_TOKEN_SUFFIX];
    ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                                          context:_requestParams];
    [req setRequestDictionary:request_data];
    [req sendRequest:^(ADAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error]);
             [req invalidate];
             return;
         }
         
         //Prefill the known elements in the item. These can be overridden by the response:
         ADTokenCacheItem* item = [ADTokenCacheItem new];
         item.resource = [_requestParams resource];
         item.clientId = [_requestParams clientId];
         item.authority = authority;
         ADAuthenticationResult* result = [item processTokenResponse:response
                                                    fromRefreshToken:nil
                                                requestCorrelationId:[_requestParams correlationId]];
         completionBlock(result);
         
         [req invalidate];
     }];
}

// Ensures that the state comes back in the response:
- (BOOL)verifyStateFromDictionary: (NSDictionary*) dictionary
{
    NSDictionary *state = [NSDictionary adURLFormDecode:[[dictionary objectForKey:OAUTH2_STATE] adBase64UrlDecode]];
    if (state.count != 0)
    {
        NSString *authorizationServer = [state objectForKey:@"a"];
        NSString *resource            = [state objectForKey:@"r"];
        
        if (![NSString adIsStringNilOrBlank:authorizationServer] && ![NSString adIsStringNilOrBlank:resource])
        {
            AD_LOG_VERBOSE_PII(_requestParams.correlationId, @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    
    AD_LOG_WARN(_requestParams.correlationId, @"Missing or invalid state returned");
    AD_LOG_WARN_PII(_requestParams.correlationId, @"Missing or invalid state returned state: %@", state);
    return NO;
}

// Encodes the state parameter for a protocol message
- (NSString *)encodeProtocolState
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:[_requestParams authority], @"a", [_requestParams resource], @"r", _requestParams.scope, @"s", nil]
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
    
    [startUrl appendFormat:@"&%@", [[ADLogger adalMetadata] adURLFormEncode]];
    
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

    NSString *claims = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:_requestParams.clientCapabilities
                                                                 developerClaims:_requestParams.decodedClaims];
    
    if (![NSString adIsStringNilOrBlank:claims])
    {
        [startUrl appendFormat:@"&%@=%@", OAUTH2_CLAIMS, claims.adUrlFormEncode];
    }
    
    return startUrl;
}

- (void)launchWebView:(NSString*)startUrl
      completionBlock:(void (^)(ADAuthenticationError*, NSURL*))completionBlock
{
    [[ADWebAuthController sharedInstance] start:[NSURL URLWithString:startUrl]
                                            end:[NSURL URLWithString:[_requestParams redirectUri]]
                                    refreshCred:_refreshTokenCredential
#if TARGET_OS_IPHONE
                                         parent:_context.parentController
                                     fullScreen:[ADAuthenticationSettings sharedInstance].enableFullScreen
#endif
                                        webView:_context.webView
                                        context:_requestParams
                                     completion:completionBlock];
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    AD_LOG_VERBOSE(_requestParams.correlationId, @"Requesting authorization code");
    AD_LOG_VERBOSE_PII(_requestParams.correlationId, @"Requesting authorization code for resource: %@", _requestParams.resource);
    
    NSString* startUrl = [self generateQueryStringForRequestType:OAUTH2_CODE];
    
    void(^requestCompletion)(ADAuthenticationError *error, NSURL *end) = ^void(ADAuthenticationError *error, NSURL *end)
    {
        [ADAuthenticationRequest releaseExclusionLock]; // Allow other operations that use the UI for credentials.
         
        NSString *code = nil;
        
        if (!error)
        {
             if ([[[end scheme] lowercaseString] isEqualToString:@"msauth"]) {
#if AD_BROKER
                 
                 NSString* host = [end host];
                 if ([host isEqualToString:@"microsoft.aad.brokerplugin"] || [host isEqualToString:@"code"])
                 {
                     NSDictionary* queryParams = [end adQueryParameters];
                     code = [queryParams objectForKey:OAUTH2_CODE];
                     [self setCloudInstanceHostname:[queryParams objectForKey:AUTH_CLOUD_INSTANCE_HOST_NAME]];
                 }
                 else
                 {
                     NSMutableDictionary *userInfoDictionary = [NSMutableDictionary dictionary];
                     NSDictionary *queryParameters = [NSDictionary adURLFormDecode:[end query]];
                     NSString *userName = [queryParameters valueForKey:AUTH_USERNAME_KEY];
                     
                     if (![NSString adIsStringNilOrBlank:userName])
                     {
                         [userInfoDictionary setObject:userName forKey:AUTH_USERNAME_KEY];
                     }
                     
                     NSError* err = [NSError errorWithDomain:ADAuthenticationErrorDomain
                                                        code:AD_ERROR_SERVER_WPJ_REQUIRED
                                                    userInfo:userInfoDictionary];
                     error = [ADAuthenticationError errorFromNSError:err errorDetails:@"work place join is required" correlationId:_requestParams.correlationId];
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
                     
                     [self setCloudInstanceHostname:[parameters objectForKey:AUTH_CLOUD_INSTANCE_HOST_NAME]];
                     
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
                       @"1", @"nux",
                       @"none", @"prompt", nil];
        
        if (![NSString adIsStringNilOrBlank:_requestParams.scope])
        {
            [requestData setObject:_requestParams.scope forKey:OAUTH2_SCOPE];
        }

        NSString *claims = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:_requestParams.clientCapabilities
                                                                     developerClaims:_requestParams.decodedClaims];
        
        if (![NSString adIsStringNilOrBlank:claims])
        {
            [requestData setObject:claims forKey:OAUTH2_CLAIMS];
        }
        
        if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString adIsStringNilOrBlank:[_requestParams identifier].userId])
        {
            [requestData setObject:_requestParams.identifier.userId forKey:OAUTH2_LOGIN_HINT];
        }
        
        NSURL* reqURL = [NSURL URLWithString:[_context.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX]];
        ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:reqURL
                                                              context:_requestParams];
        [req setIsGetRequest:YES];
        [req setRequestDictionary:requestData];
        [req sendRequest:^(ADAuthenticationError *error, NSDictionary * parameters)
         {
             if (error && ![parameters objectForKey:@"url"]) // auth code and OAuth2 error could be in endURL
             {
                 requestCompletion(error, nil);
                 [req invalidate];
                 return;
             }
             
             //Auth code and OAuth2 error may be passed in endURL
             NSURL* endURL = [parameters objectForKey:@"url"];
             error = nil;

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
             [req invalidate];
         }];
    }
}

@end
