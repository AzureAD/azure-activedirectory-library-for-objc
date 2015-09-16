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

#import "ADAuthenticationContext+Internal.h"
#import "ADWebRequest.h"
#import "ADWorkPlaceJoinConstants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADClientMetrics.h"
#import "ADWebResponse.h"
#import "ADPkeyAuthHelper.h"
#import "ADAuthenticationSettings.h"
#import "ADAuthenticationBroker.h"
#import "ADHelpers.h"
#import "NSURL+ADExtensions.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"

#import <libkern/OSAtomic.h>

@implementation ADAuthenticationRequest (WebRequest)

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
         ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
         item.resource = _resource;
         item.clientId = _clientId;
         completionBlock([_context processTokenResponse:response
                                                forItem:item
                                            fromRefresh:NO
                                   requestCorrelationId:_correlationId]);
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
                 completion:completionBlock];
}

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
             isGetRequest:(BOOL)isGetRequest
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [self ensureRequest];
    NSString* endPoint = _context.authority;
    
    if(!isHandlingPKeyAuthChallenge && !isGetRequest)
	{
        endPoint = [_context.authority stringByAppendingString:OAUTH2_TOKEN_SUFFIX];
    }
    
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:[NSURL URLWithString:endPoint]
                                                   correlationId:_correlationId];
    
    if(isGetRequest)
    {
        webRequest.method = HTTPGet;
    }
    else
    {
        webRequest.method = HTTPPost;
        webRequest.body = [[request_data adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    }
    
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
        AD_LOG_VERBOSE_F(@"Get request", @"Sending GET request to %@ with client-request-id %@", endPoint, [_correlationId UUIDString]);
    }
    else
    {
        AD_LOG_VERBOSE_F(@"Post request", @"Sending POST request to %@ with client-request-id %@", endPoint, [_correlationId UUIDString]);
    }
    
    webRequest.body = [[request_data adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    [[ADClientMetrics getInstance] beginClientMetricsRecordForEndpoint:endPoint correlationId:[_correlationId UUIDString] requestHeader:webRequest.headers];
    
    [webRequest send:^( NSError *error, ADWebResponse *webResponse ) {
        // Request completion callback
        NSMutableDictionary *response = [NSMutableDictionary new];
        
        if ( error == nil )
        {
            NSDictionary* headers = webResponse.headers;
            //In most cases the correlation id is returned as a separate header
            NSString* responseCorrelationId = [headers objectForKey:OAUTH2_CORRELATION_ID_REQUEST_VALUE];
            if (![NSString adIsStringNilOrBlank:responseCorrelationId])
            {
                [response setObject:responseCorrelationId forKey:OAUTH2_CORRELATION_ID_RESPONSE];//Add it to the dictionary to be logged and checked later.
            }
            
            [response setObject:webResponse.URL forKey:@"url"];
            
            switch (webResponse.statusCode)
            {
                case 200:
                    if(returnRawResponse)
                    {
                        [response setObject:[[NSString alloc] initWithData:webResponse.body encoding:NSASCIIStringEncoding]
                                     forKey:@"raw_response"];
                        break;
                    }
                case 400:
                case 401:
                {
                    if(!isHandlingPKeyAuthChallenge){
                        NSString* wwwAuthValue = [headers valueForKey:wwwAuthenticateHeader];
                        if(![NSString adIsStringNilOrBlank:wwwAuthValue] && [wwwAuthValue adContainsString:pKeyAuthName]){
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
                        ADAuthenticationError* adError;
                        if (jsonError)
                        {
                            // Unrecognized JSON response
                            NSString* bodyStr = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
                            AD_LOG_ERROR_F(@"JSON deserialization", jsonError.code, @"Error: %@. Body text: '%@'. HTTPS Code: %ld. Response correlation id: %@", jsonError.description, bodyStr, (long)webResponse.statusCode, responseCorrelationId);
                            adError = [ADAuthenticationError errorFromNSError:jsonError errorDetails:jsonError.localizedDescription];
                        }
                        else
                        {
                            adError = [ADAuthenticationError unexpectedInternalError:[NSString stringWithFormat:@"Unexpected object type: %@", [jsonObject class]]];
                        }
                        [response setObject:adError forKey:AUTH_NON_PROTOCOL_ERROR];
                    }
                }
                    break;
                default:
                {
                    // Request failure
                    NSString* body = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
                    NSString* errorData = [NSString stringWithFormat:@"Server HTTP status code: %ld. Full response %@", (long)webResponse.statusCode, body];
                    AD_LOG_WARN(@"HTTP Error", errorData);
                    
                    //Now add the information to the dictionary, so that the parser can extract it:
                    [response setObject:[ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION protocolCode:@(webResponse.statusCode).stringValue errorDetails:errorData]
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
            AD_LOG_WARN(@"System error while making request.", error.description);
            // System error
            [response setObject:[ADAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription]
                         forKey:AUTH_NON_PROTOCOL_ERROR];
        }
        
        if([response valueForKey:AUTH_NON_PROTOCOL_ERROR]){
            [[ADClientMetrics getInstance] endClientMetricsRecord:[[response valueForKey:AUTH_NON_PROTOCOL_ERROR] errorDetails]];
        }
        else
        {
            [[ADClientMetrics getInstance] endClientMetricsRecord:nil];
        }
        
        completionBlock( response );
    }];
}

//Used for the callback of obtaining the OAuth2 code:
static volatile int sDialogInProgress = 0;

//Ensures that a single UI login dialog can be requested at a time.
//Returns true if successfully acquired the lock. If not, calls the callback with
//the error and returns false.
-(BOOL) takeExclusionLockWithCallback: (ADAuthorizationCodeCallback) completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    if ( !OSAtomicCompareAndSwapInt( 0, 1, &sDialogInProgress) )
    {
        NSString* message = @"The user is currently prompted for credentials as result of another acquireToken request. Please retry the acquireToken call later.";
        ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_PROMPTED
                                                                              protocolCode:nil
                                                                              errorDetails:message];
        completionBlock(nil, error);
        return NO;
    }
    return YES;
}

//Attempts to release the lock. Logs warning if the lock was already released.
-(void) releaseExclusionLock
{
    if ( !OSAtomicCompareAndSwapInt( 1, 0, &sDialogInProgress) )
    {
        AD_LOG_WARN(@"UI Locking", @"The UI lock has already been released.");
    }
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
            AD_LOG_VERBOSE_F(@"State", @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    AD_LOG_WARN_F(@"State error", @"Missing or invalid state returned: %@", state);
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

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(ADAuthorizationCodeCallback)completionBlock
{
    [self requestCodeWithRefreshTokenCredential:nil completionBlock:completionBlock];

}
//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCodeWithRefreshTokenCredential:(NSString*)refreshTokenCredential
                              completionBlock:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    AD_LOG_VERBOSE_F(@"Requesting authorization code.", @"Requesting authorization code for resource: %@", _resource);
    if (!_silent && ![self takeExclusionLockWithCallback:completionBlock])
    {
        return;
    }
    
    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
    NSString* startUrl = [self generateQueryStringForRequestType:OAUTH2_CODE];
    
    void(^requestCompletion)(ADAuthenticationError *error, NSURL *end) = ^void(ADAuthenticationError *error, NSURL *end)
    {
         if (!_silent)
         {
             [self releaseExclusionLock]; // Allow other operations that use the UI for credentials.
         }
         
         NSString* code = nil;
         if (!error)
         {
             
             if ([[[end scheme] lowercaseString] isEqualToString:@"msauth"]) {
#if AD_BROKER
                 
                 NSDictionary* userInfo = @{
                                            @"username": [[NSDictionary adURLFormDecode:[end query]] valueForKey:@"username"],
                                            };
                 NSError* err = [NSError errorWithDomain:ADAuthenticationErrorDomain
                                                    code:AD_ERROR_WPJ_REQUIRED
                                                userInfo:userInfo];
                 error = [ADAuthenticationError errorFromNSError:err errorDetails:@"work place join is required"];
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
                 error = [ADAuthenticationContext errorFromDictionary:parameters errorCode:AD_ERROR_AUTHENTICATION];
                 if (!error)
                 {
                     //Note that we do not enforce the state, just log it:
                     [self verifyStateFromDictionary:parameters];
                     code = [parameters objectForKey:OAUTH2_CODE];
                     if ([NSString adIsStringNilOrBlank:code])
                     {
                         error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION
                                                                        protocolCode:nil
                                                                        errorDetails:@"The authorization server did not return a valid authorization code."];
                     }
                 }
             }
         }
         
         completionBlock(code, error);
     };
    
    if (!_silent)
    {
        [[ADAuthenticationBroker sharedInstance] start:[NSURL URLWithString:startUrl]
                                                   end:[NSURL URLWithString:_redirectUri]
                                refreshTokenCredential:refreshTokenCredential
                                      parentController:_context.parentController
                                               webView:_context.webView
                                            fullScreen:settings.enableFullScreen
                                         correlationId:_correlationId
                                            completion:requestCompletion];
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
                     completion:^(NSDictionary * parameters)
         {
             
             NSURL* endURL = nil;
             ADAuthenticationError* error = nil;
             
             //OAuth2 error may be passed by the server
             endURL = [parameters objectForKey:@"url"];
             if (!endURL)
             {
                 error = [ADAuthenticationContext errorFromDictionary:parameters errorCode:AD_ERROR_AUTHENTICATION];
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
    wwwAuthHeaderValue = [wwwAuthHeaderValue stringByReplacingOccurrencesOfString:@"\""
                                                                       withString:@""];
    NSArray* headerPairs = [wwwAuthHeaderValue componentsSeparatedByString:@","];
    NSMutableDictionary* headerKeyValuePair = [[NSMutableDictionary alloc]init];
    for(int i=0; i<[headerPairs count]; ++i) {
        NSArray* pair = [headerPairs[i] componentsSeparatedByString:@"="];
        [headerKeyValuePair setValue:pair[1] forKey:[pair[0] adTrimmedString]];
    }
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer
                                                        challengeData:headerKeyValuePair];
    [headerKeyValuePair removeAllObjects];
    [headerKeyValuePair setObject:authHeader forKey:@"Authorization"];
    
    [self requestWithServer:authorizationServer
                requestData:request_data
            handledPkeyAuth:TRUE
          additionalHeaders:headerKeyValuePair
                 completion:completionBlock];
}


@end
