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

#import <libkern/OSAtomic.h>

@implementation ADAuthenticationContext (WebRequest)

- (void)executeRequest:(NSString *)authorizationServer
           requestData:(NSDictionary *)request_data
              resource:(NSString *) resource
              clientId:(NSString*) clientId
  requestCorrelationId:(NSUUID*) requestCorrelationId
       handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
     additionalHeaders:(NSDictionary *)additionalHeaders
            completion:(ADAuthenticationCallback)completionBlock
{
    [self requestWithServer:authorizationServer
                requestData:request_data
       requestCorrelationId:requestCorrelationId
            handledPkeyAuth:isHandlingPKeyAuthChallenge
          additionalHeaders:additionalHeaders
                 completion:^(NSDictionary *response)
     {
         //Prefill the known elements in the item. These can be overridden by the response:
         ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
         item.resource = resource;
         item.clientId = clientId;
         completionBlock([self processTokenResponse:response
                                            forItem:item
                                        fromRefresh:NO
                               requestCorrelationId:requestCorrelationId]);
     }];
}


// Performs an OAuth2 token request using the supplied request dictionary and executes the completion block
// If the request generates an HTTP error, the method adds details to the "error" parameters of the dictionary.
- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
               completion:( void (^)(NSDictionary *) )completionBlock
{
    [self requestWithServer:authorizationServer
                requestData:request_data
       requestCorrelationId:requestCorrelationId
            handledPkeyAuth:isHandlingPKeyAuthChallenge
          additionalHeaders:additionalHeaders
          returnRawResponse:NO
                 completion:completionBlock];
}

- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
        returnRawResponse:(BOOL)returnRawResponse
               completion:( void (^)(NSDictionary *) )completionBlock
{
    NSString* endPoint = authorizationServer;
    
    if(!isHandlingPKeyAuthChallenge){
        endPoint = [authorizationServer stringByAppendingString:OAUTH2_TOKEN_SUFFIX];
    }
    
    ADWebRequest *webRequest = [[ADWebRequest alloc] initWithURL:[NSURL URLWithString:endPoint]
                                                   correlationId:requestCorrelationId];
    
    webRequest.method = HTTPPost;
    [webRequest.headers setObject:@"application/json" forKey:@"Accept"];
    [webRequest.headers setObject:@"application/x-www-form-urlencoded" forKey:@"Content-Type"];
    [webRequest.headers setObject:pKeyAuthHeaderVersion forKey:pKeyAuthHeader];
    if(additionalHeaders){
        for (NSString* key in [additionalHeaders allKeys] ) {
            [webRequest.headers setObject:[additionalHeaders objectForKey:key ] forKey:key];
        }
    }
    
    AD_LOG_VERBOSE_F(@"Post request", @"Sending POST request to %@ with client-request-id %@", endPoint, [requestCorrelationId UUIDString]);
    
    webRequest.body = [[request_data adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    [[ADClientMetrics getInstance] beginClientMetricsRecordForEndpoint:endPoint correlationId:[requestCorrelationId UUIDString] requestHeader:webRequest.headers];
    
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
                        [response setObject:[[NSString alloc] initWithData:webResponse.body encoding:0]
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
                                     requestCorrelationId:requestCorrelationId
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
- (NSString *)encodeProtocolStateWithResource:(NSString *)resource scope:(NSString *)scope
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:self.authority, @"a", resource, @"r", scope, @"s", nil]
             adURLFormEncode] adBase64UrlEncode];
}

//Generates the query string, encoding the state:
- (NSString*)queryStringFromResource:(NSString*)resource
                            clientId:(NSString*)clientId
                         redirectUri:(NSURL*)redirectUri
                               scope:(NSString*)scope /* for future use */
                              userId:(NSString*)userId
                         requestType:(NSString*)requestType
                      promptBehavior:(ADPromptBehavior)promptBehavior
                extraQueryParameters:(NSString*)queryParams
{
    NSString *state    = [self encodeProtocolStateWithResource:resource scope:scope];
    // Start the web navigation process for the Implicit grant profile.
    NSMutableString *startUrl = [NSMutableString stringWithFormat:@"%@?%@=%@&%@=%@&%@=%@&%@=%@&%@=%@",
                                 [self.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX],
                                 OAUTH2_RESPONSE_TYPE, requestType,
                                 OAUTH2_CLIENT_ID, [clientId adUrlFormEncode],
                                 OAUTH2_RESOURCE, [resource adUrlFormEncode],
                                 OAUTH2_REDIRECT_URI, [[redirectUri absoluteString] adUrlFormEncode],
                                 OAUTH2_STATE, state];
    
    [startUrl appendFormat:@"&%@", [[ADLogger adalId] adURLFormEncode]];
    
    if (![NSString adIsStringNilOrBlank:userId])
    {
        [startUrl appendFormat:@"&%@=%@", OAUTH2_LOGIN_HINT, [userId adUrlFormEncode]];
    }
    NSString* promptParam = [ADAuthenticationContext getPromptParameter:promptBehavior];
    if (promptParam)
    {
        //Force the server to ignore cookies, by specifying explicitly the prompt behavior:
        [startUrl appendString:[NSString stringWithFormat:@"&prompt=%@", promptParam]];
    }
    if (![NSString adIsStringNilOrBlank:queryParams])
    {//Append the additional query parameters if specified:
        queryParams = queryParams.adTrimmedString;
        
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
- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock
{
    [self requestCodeByResource:resource
                       clientId:clientId
                    redirectUri:redirectUri
                          scope:scope
                         userId:userId
                 promptBehavior:promptBehavior
           extraQueryParameters:queryParams
         refreshTokenCredential:nil
                         silent:NO
                  correlationId:correlationId
                     completion:completionBlock];

}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
       refreshTokenCredential:(NSString*)refreshTokenCredential
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock
{
    [self requestCodeByResource:resource clientId:clientId
                    redirectUri:redirectUri
                          scope:scope
                         userId:userId
                 promptBehavior:promptBehavior
           extraQueryParameters:queryParams
         refreshTokenCredential:refreshTokenCredential
                         silent:NO
                  correlationId:correlationId
                     completion:completionBlock];
}


//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCodeByResource:(NSString*)resource
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                        scope:(NSString*)scope /*for future use */
                       userId:(NSString*)userId
               promptBehavior:(ADPromptBehavior)promptBehavior
         extraQueryParameters:(NSString*)queryParams
       refreshTokenCredential:(NSString*)refreshTokenCredential
                       silent:(BOOL)silent
                correlationId:(NSUUID*)correlationId
                   completion:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    if(!correlationId){
        completionBlock(nil, [ADAuthenticationError errorFromArgument:correlationId argumentName:@"correlationId"]);
        return;
    }
    
    AD_LOG_VERBOSE_F(@"Requesting authorization code.", @"Requesting authorization code for resource: %@", resource);
    if (!silent && ![self takeExclusionLockWithCallback:completionBlock])
    {
        return;
    }
    
    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
    NSString* startUrl = [self queryStringFromResource:resource
                                              clientId:clientId
                                           redirectUri:redirectUri
                                                 scope:scope
                                                userId:userId
                                           requestType:OAUTH2_CODE
                                        promptBehavior:promptBehavior
                                  extraQueryParameters:queryParams];
    
    void(^requestCompletion)(ADAuthenticationError *error, NSURL *end) = ^void(ADAuthenticationError *error, NSURL *end)
    {
         if (!silent)
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
    
    if (!silent)
    {
        [[ADAuthenticationBroker sharedInstance] start:[NSURL URLWithString:startUrl]
                                                   end:[NSURL URLWithString:[redirectUri absoluteString]]
                                refreshTokenCredential:refreshTokenCredential
                                      parentController:self.parentController
                                               webView:self.webView
                                            fullScreen:settings.enableFullScreen
                                         correlationId:correlationId
                                            completion:requestCompletion];
    }
    else
    {
        NSMutableDictionary* requestData = nil;
        requestData = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                       clientId, OAUTH2_CLIENT_ID,
                       [redirectUri absoluteString], OAUTH2_REDIRECT_URI,
                       resource, OAUTH2_RESOURCE,
                       OAUTH2_CODE, OAUTH2_RESPONSE_TYPE, nil];
        
        if (scope)
        {
            [requestData setObject:scope forKey:OAUTH2_SCOPE];
        }
        
        [self requestWithServer:[self.authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX]
                    requestData:requestData
           requestCorrelationId:correlationId
                handledPkeyAuth:NO
              additionalHeaders:nil
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
            requestCorrelationId: (NSUUID*) requestCorrelationId
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
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer challengeData:headerKeyValuePair challengeType:AD_THUMBPRINT];
    [headerKeyValuePair removeAllObjects];
    [headerKeyValuePair setObject:authHeader forKey:@"Authorization"];
    
    [self requestWithServer:authorizationServer
                requestData:request_data
       requestCorrelationId:requestCorrelationId
            handledPkeyAuth:TRUE
          additionalHeaders:headerKeyValuePair
                 completion:completionBlock];
}


@end
