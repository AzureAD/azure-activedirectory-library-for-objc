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

#import <libkern/OSAtomic.h>

static ADAuthenticationRequest* s_modalRequest = nil;

@implementation ADAuthenticationRequest (WebRequest)

+ (ADAuthenticationRequest*)currentModalRequest
{
    return s_modalRequest;
}

- (void)executeRequest:(NSString *)authorizationServer
           requestData:(NSDictionary *)request_data
       handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
     additionalHeaders:(NSDictionary *)additionalHeaders
            completion:(ADAuthenticationCallback)completionBlock
{
    [self requestWithServer:authorizationServer
                requestData:request_data
            handledPkeyAuth:isHandlingPKeyAuthChallenge
          additionalHeaders:additionalHeaders
                 completion:^(NSDictionary *response)
     {
         //Prefill the known elements in the item. These can be overridden by the response:
         ADTokenCacheItem* item = [ADTokenCacheItem new];
         item.resource = _resource;
         item.clientId = _clientId;
         item.authority = _context.authority;
         ADAuthenticationResult* result = [item processTokenResponse:response
                                                         fromRefresh:NO
                                                requestCorrelationId:_correlationId];
         SAFE_ARC_RELEASE(item);
         completionBlock(result);
     }];
}


// Performs an OAuth2 token request using the supplied request dictionary and executes the completion block
// If the request generates an HTTP error, the method adds details to the "error" parameters of the dictionary.
- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [self requestWithServer:authorizationServer
                requestData:request_data
            handledPkeyAuth:isHandlingPKeyAuthChallenge
          additionalHeaders:additionalHeaders
          returnRawResponse:NO
               isGetRequest:NO
         retryIfServerError:YES
                 completion:completionBlock];
}


- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [self requestWithServer:authorizationServer
                requestData:request_data
            handledPkeyAuth:isHandlingPKeyAuthChallenge
          additionalHeaders:additionalHeaders
          returnRawResponse:returnRawResponse
               isGetRequest:NO
         retryIfServerError:YES
                 completion:completionBlock];
}

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
             isGetRequest:(BOOL)isGetRequest
       retryIfServerError:(BOOL)retryIfServerError
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [self ensureRequest];
    NSString* endPoint = authorizationServer;
    
    if (!isHandlingPKeyAuthChallenge && !isGetRequest)
	{
        endPoint = [_context.authority stringByAppendingString:OAUTH2_TOKEN_SUFFIX];
    }
    
    if (isGetRequest)
    {
        endPoint = [NSString stringWithFormat:@"%@?%@", endPoint, [request_data adURLFormEncode]];
    }
    
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:[NSURL URLWithString:endPoint]
                                                   correlationId:_correlationId];
    [webRequest setMethodType:isGetRequest ? ADWebRequestGet : ADWebRequestPost];
    [webRequest.headers setObject:@"application/json" forKey:@"Accept"];
    [webRequest.headers setObject:@"application/x-www-form-urlencoded" forKey:@"Content-Type"];
    [webRequest.headers setObject:pKeyAuthHeaderVersion forKey:pKeyAuthHeader];
    if(additionalHeaders){
        for (NSString* key in [additionalHeaders allKeys] ) {
            [webRequest.headers setObject:[additionalHeaders objectForKey:key ] forKey:key];
        }
    }
    
    if (isGetRequest)
    {
        AD_LOG_VERBOSE_F(@"Get request", _correlationId, @"Sending GET request to %@ with client-request-id %@", endPoint, [_correlationId UUIDString]);
    }
    else
    {
        AD_LOG_VERBOSE_F(@"Post request", _correlationId, @"Sending POST request to %@ with client-request-id %@", endPoint, [_correlationId UUIDString]);
    }
    
    webRequest.body = [[request_data adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    
    __block NSDate* startTime = [NSDate new];
    [[ADClientMetrics getInstance] addClientMetrics:webRequest.headers endpoint:endPoint];
    
    [webRequest send:^( NSError *error, ADWebResponse *webResponse ) {
        // Request completion callback
        NSMutableDictionary *response = [NSMutableDictionary new];
        SAFE_ARC_AUTORELEASE(response);
        
        if ( error == nil )
        {
            NSDictionary* headers = webResponse.headers;
            //In most cases the correlation id is returned as a separate header
            NSString* responseCorrelationId = [headers objectForKey:OAUTH2_CORRELATION_ID_REQUEST_VALUE];
            NSUUID* responseCorrelationUUID = _correlationId;
            if (![NSString adIsStringNilOrBlank:responseCorrelationId])
            {
                [response setObject:responseCorrelationId forKey:OAUTH2_CORRELATION_ID_RESPONSE];//Add it to the dictionary to be logged and checked later.
                responseCorrelationUUID = [[NSUUID alloc] initWithUUIDString:responseCorrelationId];
                SAFE_ARC_AUTORELEASE(responseCorrelationUUID);
            }
            
            [response setObject:webResponse.URL forKey:@"url"];
            
            switch (webResponse.statusCode)
            {
                case 200:
                    if(returnRawResponse)
                    {
                        NSString* rawResponse = [[NSString alloc] initWithData:webResponse.body encoding:NSASCIIStringEncoding];
                        [response setObject:rawResponse
                                     forKey:@"raw_response"];
                        SAFE_ARC_RELEASE(rawResponse);
                        break;
                    }
                case 400:
                case 401:
                {
                    if(!isHandlingPKeyAuthChallenge)
                    {
                        NSString* wwwAuthValue = [headers valueForKey:wwwAuthenticateHeader];
                        if(![NSString adIsStringNilOrBlank:wwwAuthValue] && [wwwAuthValue adContainsString:pKeyAuthName])
                        {
                            [self handlePKeyAuthChallenge:endPoint
                                       wwwAuthHeaderValue:wwwAuthValue
                                              requestData:request_data
                                               completion:completionBlock];
                            return;
                        }
                    }
                    NSError   *jsonError  = nil;
                    id         jsonObject = [NSJSONSerialization JSONObjectWithData:webResponse.body options:0 error:&jsonError];
                    
                    if ( nil != jsonObject && [jsonObject isKindOfClass:[NSDictionary class]] )
                    {
                        // Load the response
                        [response addEntriesFromDictionary:(NSDictionary*)jsonObject];
                    }
                    else
                    {
                        ADAuthenticationError* adError = nil;
                        if (jsonError)
                        {
                            // Unrecognized JSON response
                            // We're often seeing the JSON parser being asked to parse whole HTML pages.
                            // Logging out the whole thing is unhelpful as it contains no useful info.
                            // If the body is > 1 KB then it's a pretty safe bet that it contains more
                            // noise then would be helpful
                            NSString* bodyStr = nil;
                            
                            if ([webResponse.body length] < 1024)
                            {
                                bodyStr = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
                            }
                            else
                            {
                                bodyStr = [[NSString alloc] initWithFormat:@"large response, probably HTML, <%lu bytes>", (unsigned long)[webResponse.body length]];
                            }
                            
                            AD_LOG_ERROR_F(@"JSON deserialization", jsonError.code, _correlationId, @"Error: %@. Body text: '%@'. HTTPS Code: %ld. Response correlation id: %@", jsonError.description, bodyStr, (long)webResponse.statusCode, responseCorrelationId);
                            adError = [ADAuthenticationError errorFromNSError:jsonError errorDetails:jsonError.localizedDescription correlationId:responseCorrelationUUID];
                            SAFE_ARC_RELEASE(bodyStr);
                        }
                        else
                        {
                            adError = [ADAuthenticationError unexpectedInternalError:[NSString stringWithFormat:@"Unexpected object type: %@", [jsonObject class]] correlationId:responseCorrelationUUID];
                        }
                        [response setObject:adError forKey:AUTH_NON_PROTOCOL_ERROR];
                    }
                }
                    break;
                case 500:
                case 503:
                {
                    //retry if it is a server error
                    //500 and 503 are the ones we retry
                    if (retryIfServerError)
                    {
                        //retry once after half second
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            [self requestWithServer:authorizationServer
                                        requestData:request_data
                                    handledPkeyAuth:isHandlingPKeyAuthChallenge
                                  additionalHeaders:additionalHeaders
                                  returnRawResponse:returnRawResponse
                                       isGetRequest:isGetRequest
                                 retryIfServerError:NO
                                         completion:completionBlock];
                        });
                        return;
                    }
                    //no "break;" here
                    //will go to default for handling if "retryIfServerError" is NO
                }
                default:
                {
                    // Request failure
                    NSString* body = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
                    NSString* errorData = [NSString stringWithFormat:@"Full response: %@", body];
                    AD_LOG_WARN(([NSString stringWithFormat:@"HTTP Error %ld", (long)webResponse.statusCode]), _correlationId, errorData);
                    
                    ADAuthenticationError* adError = [ADAuthenticationError HTTPErrorCode:webResponse.statusCode
                                                                                     body:[NSString stringWithFormat:@"(%lu bytes)", (unsigned long)webResponse.body.length]
                                                                            correlationId:_correlationId];
                    SAFE_ARC_RELEASE(body);
                    
                    //Now add the information to the dictionary, so that the parser can extract it:
                    [response setObject:adError
                                 forKey:AUTH_NON_PROTOCOL_ERROR];
                }
            }
        }
        else if (error && [[error domain] isEqualToString:@"NSURLErrorDomain"] && [error code] == -1002)
        {
            // Unsupported URL Error
            // This can happen because the redirect URI isn't a valid URI, or we've tried to jump out of the app with a URL scheme handler
            // It's worth peeking into this error to see if we have useful information anyways.
            
            NSString* url = [[error userInfo] objectForKey:@"NSErrorFailingURLKey"];
            [response setObject:url forKey:@"url"];
        }
        else
        {
            AD_LOG_WARN(@"System error while making request.", _correlationId, error.description);
            // System error
            ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error
                                                                        errorDetails:error.localizedDescription
                                                                       correlationId:_correlationId];
            
            [response setObject:adError
                         forKey:AUTH_NON_PROTOCOL_ERROR];
        }
        
        ADAuthenticationError* adError = [response valueForKey:AUTH_NON_PROTOCOL_ERROR];
        NSString* errorDetails = [adError errorDetails];
        [[ADClientMetrics getInstance] endClientMetricsRecord:endPoint
                                                    startTime:startTime
                                                correlationId:_correlationId
                                                 errorDetails:errorDetails];
        SAFE_ARC_RELEASE(startTime);
        
        completionBlock(response);
    }];
    
    // The objc blocks above will hold onto references to this web request and keep it alive until after
    // the completion block gets hit.
    SAFE_ARC_RELEASE(webRequest);
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
                                                                             correlationId:_correlationId];
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
            AD_LOG_VERBOSE_F(@"State", _correlationId, @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    AD_LOG_WARN_F(@"State error", _correlationId, @"Missing or invalid state returned: %@", state);
    return NO;
}

// Encodes the state parameter for a protocol message
- (NSString *)encodeProtocolState
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:_context.authority, @"a", _resource, @"r", _scope, @"s", nil]
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
                                 OAUTH2_CLIENT_ID, [_clientId adUrlFormEncode],
                                 OAUTH2_RESOURCE, [_resource adUrlFormEncode],
                                 OAUTH2_REDIRECT_URI, [_redirectUri adUrlFormEncode],
                                 OAUTH2_STATE, state];
    
    [startUrl appendFormat:@"&%@", [[ADLogger adalId] adURLFormEncode]];
    
    if (_identifier && [_identifier isDisplayable] && ![NSString adIsStringNilOrBlank:_identifier.userId])
    {
        [startUrl appendFormat:@"&%@=%@", OAUTH2_LOGIN_HINT, [_identifier.userId adUrlFormEncode]];
    }
    NSString* promptParam = [ADAuthenticationContext getPromptParameter:_promptBehavior];
    if (promptParam)
    {
        //Force the server to ignore cookies, by specifying explicitly the prompt behavior:
        [startUrl appendString:[NSString stringWithFormat:@"&prompt=%@", promptParam]];
    }
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
    [[ADWebAuthController sharedInstance] start:[NSURL URLWithString:startUrl]
                                            end:[NSURL URLWithString:_redirectUri]
                                    refreshCred:_refreshTokenCredential
#if TARGET_OS_IPHONE
                                         parent:_context.parentController
                                     fullScreen:[ADAuthenticationSettings sharedInstance].enableFullScreen
#endif
                                        webView:_context.webView
                                  correlationId:_correlationId
                                     completion:completionBlock];
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    AD_LOG_VERBOSE_F(@"Requesting authorization code.", _correlationId, @"Requesting authorization code for resource: %@", _resource);
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
                                                        code:AD_ERROR_WPJ_REQUIRED
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
                                                                       correlationId:_correlationId];
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
                       _clientId, OAUTH2_CLIENT_ID,
                       _redirectUri, OAUTH2_REDIRECT_URI,
                       _resource, OAUTH2_RESOURCE,
                       OAUTH2_CODE, OAUTH2_RESPONSE_TYPE,
					   @"1", @"nux", nil];
        
        if (_scope)
        {
            [requestData setObject:_scope forKey:OAUTH2_SCOPE];
        }
        
        [self requestWithServer:[_context.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX]
                    requestData:requestData
                handledPkeyAuth:NO
              additionalHeaders:nil
              returnRawResponse:NO
				   isGetRequest:YES
             retryIfServerError:YES
                     completion:^(NSDictionary * parameters)
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

- (void) handlePKeyAuthChallenge:(NSString *)authorizationServer
              wwwAuthHeaderValue:(NSString *)wwwAuthHeaderValue
                     requestData:(NSDictionary *)request_data
                      completion:( void (^)(NSDictionary *) )completionBlock
{
    //pkeyauth word length=8 + 1 whitespace
    wwwAuthHeaderValue = [wwwAuthHeaderValue substringFromIndex:[pKeyAuthName length] + 1];
    
    NSDictionary* authHeaderParams = [wwwAuthHeaderValue authHeaderParams];
    
    if (!authHeaderParams)
    {
        AD_LOG_ERROR_F(@"Unparseable wwwAuthHeader received.", AD_ERROR_SERVER_WPJ_REQUIRED, _correlationId, @"%@", wwwAuthHeaderValue);
    }
    
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer
                                                        challengeData:authHeaderParams];
    
    NSDictionary* additionalHeaders = @{ @"Authorization" : authHeader };

    
    [self requestWithServer:authorizationServer
                requestData:request_data
            handledPkeyAuth:TRUE
          additionalHeaders:additionalHeaders
                 completion:completionBlock];
}


@end
