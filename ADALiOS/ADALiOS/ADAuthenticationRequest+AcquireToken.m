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
#import "ADInstanceDiscovery.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"

@implementation ADAuthenticationContext (AcquireToken)

#pragma mark -
#pragma mark AcquireToken
- (void)internalAcquireTokenWithResource:(NSString*)resource
                                clientId:(NSString*)clientId
                             redirectUri:(NSURL*)redirectUri
                          promptBehavior:(ADPromptBehavior)promptBehavior
                                  silent:(BOOL)silent /* Do not show web UI for authorization. */
                                  userId:(NSString*)userId
                                   scope:(NSString*)scope
                    extraQueryParameters:(NSString*)queryParams
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock
{
    ADUserIdentifier* identifier = [ADUserIdentifier identifierWithId:userId
                                                                 type:RequiredDisplayableId];
    [self internalAcquireTokenWithResource:resource
                                  clientId:clientId
                               redirectUri:redirectUri
                            promptBehavior:promptBehavior
                                    silent:silent
                            userIdentifier:identifier
                                     scope:scope
                      extraQueryParameters:queryParams
                         validateAuthority:validateAuthority
                             correlationId:correlationId
                           completionBlock:completionBlock];
    
}

- (void)internalAcquireTokenWithResource:(NSString*)resource
                                clientId:(NSString*)clientId
                             redirectUri:(NSURL*)redirectUri
                          promptBehavior:(ADPromptBehavior)promptBehavior
                                  silent:(BOOL)silent /* Do not show web UI for authorization. */
                          userIdentifier:(ADUserIdentifier*)userId
                                   scope:(NSString*)scope
                    extraQueryParameters:(NSString*)queryParams
                       validateAuthority:(BOOL)validateAuthority
                           correlationId:(NSUUID*)correlationId
                         completionBlock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(resource);
    
    [self updateCorrelationId:&correlationId];
    
    if (validateAuthority)
    {
        [[ADInstanceDiscovery sharedInstance] validateAuthority:self.authority correlationId:correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             if (error)
             {
                 completionBlock([ADAuthenticationResult resultFromError:error]);
             }
             else
             {
                 [self validatedAcquireTokenWithResource:resource
                                                clientId:clientId
                                             redirectUri:redirectUri
                                          promptBehavior:promptBehavior
                                                  silent:silent
                                                  userId:userId
                                                   scope:scope
                                    extraQueryParameters:queryParams
                                           correlationId:correlationId
                                         completionBlock:completionBlock];
             }
         }];
        return;//The asynchronous handler above will do the work.
    }
    
    [self validatedAcquireTokenWithResource:resource
                                   clientId:clientId
                                redirectUri:redirectUri
                             promptBehavior:promptBehavior
                                     silent:silent
                                     userId:userId
                                      scope:scope
                       extraQueryParameters:queryParams
                              correlationId:correlationId
                            completionBlock:completionBlock];
    
}

- (void)validatedAcquireTokenWithResource:(NSString*)resource
                                 clientId:(NSString*)clientId
                              redirectUri:(NSURL*)redirectUri
                           promptBehavior:(ADPromptBehavior)promptBehavior
                                   silent:(BOOL)silent /* Do not show web UI for authorization. */
                                   userId:(ADUserIdentifier*)userId
                                    scope:(NSString*)scope
                     extraQueryParameters:(NSString*)queryParams
                            correlationId:(NSUUID*)correlationId
                          completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    //Check the cache:
    ADAuthenticationError* error;
    //We are explicitly creating a key first to ensure indirectly that all of the required arguments are correct.
    //This is the safest way to guarantee it, it will raise an error, if the the any argument is not correct:
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:resource clientId:clientId error:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    if (![ADAuthenticationContext isForcedAuthorization:promptBehavior] && self.tokenCacheStore)
    {
        //Cache should be used in this case:
        BOOL accessTokenUsable;
        ADTokenCacheStoreItem* cacheItem = [self findCacheItemWithKey:key userId:userId useAccessToken:&accessTokenUsable error:&error];
        if (error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error]);
            return;
        }
        
        if (cacheItem)
        {
            //Found a promising item in the cache, try using it:
            [self attemptToUseCacheItem:cacheItem
                         useAccessToken:accessTokenUsable
                               resource:resource
                               clientId:clientId
                            redirectUri:redirectUri
                         promptBehavior:promptBehavior
                                 silent:silent
                                 userId:userId
                   extraQueryParameters:queryParams
                          correlationId:correlationId
                        completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
    }
    
    [self requestTokenWithResource:resource
                          clientId:clientId
                       redirectUri:redirectUri
                    promptBehavior:promptBehavior
                            silent:silent
                            userId:userId
                             scope:scope
              extraQueryParameters:queryParams
                     correlationId:correlationId
                   completionBlock:completionBlock];
}

- (void) requestTokenWithResource:(NSString*)resource
                         clientId:(NSString*)clientId
                      redirectUri:(NSURL*)redirectUri
                   promptBehavior:(ADPromptBehavior)promptBehavior
                           silent:(BOOL)silent /* Do not show web UI for authorization. */
                           userId:(ADUserIdentifier*)userId
                            scope:(NSString*)scope
             extraQueryParameters:(NSString*)queryParams
                    correlationId:(NSUUID*)correlationId
                  completionBlock:(ADAuthenticationCallback)completionBlock
{
#if !AD_BROKER
    if (silent)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown:
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_INPUT_NEEDED
                                               protocolCode:nil
                                               errorDetails:ADCredentialsNeeded];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
#endif
    
    [self requestTokenWithResource:resource
                          clientId:clientId
                       redirectUri:redirectUri
                    promptBehavior:promptBehavior
                       allowSilent:silent
                            userId:userId
                             scope:scope
              extraQueryParameters:queryParams
                     correlationId:correlationId
                   completionBlock:completionBlock];
}

- (void) requestTokenWithResource:(NSString*) resource
                         clientId:(NSString*) clientId
                      redirectUri:(NSURL*) redirectUri
                   promptBehavior:(ADPromptBehavior) promptBehavior
                      allowSilent:(BOOL) allowSilent
                           userId:(ADUserIdentifier*)userId
                            scope:(NSString*) scope
             extraQueryParameters:(NSString*) queryParams
                    correlationId:(NSUUID*) correlationId
                  completionBlock:(ADAuthenticationCallback)completionBlock
{
#if !AD_BROKER
    //call the broker.
    if([ADAuthenticationContext canUseBroker]){
        [self callBrokerForAuthority:self.authority
                            resource:resource
                            clientId:clientId
                         redirectUri:redirectUri
                      promptBehavior:promptBehavior
                              userId:userId
                extraQueryParameters:queryParams
                       correlationId:[correlationId UUIDString]
                     completionBlock:completionBlock
         ];
        return;
    }
#endif
    
    //Get the code first:
    [self requestCodeByResource:resource
                       clientId:clientId
                    redirectUri:redirectUri
                          scope:scope
                         userId:userId
                 promptBehavior:promptBehavior
           extraQueryParameters:queryParams
         refreshTokenCredential:nil
                         silent:allowSilent
                  correlationId:correlationId
                     completion:^(NSString * code, ADAuthenticationError *error)
     {
         if (error)
         {
             ADAuthenticationResult* result = (AD_ERROR_USER_CANCEL == error.code) ? [ADAuthenticationResult resultFromCancellation]
             : [ADAuthenticationResult resultFromError:error];
             completionBlock(result);
         }
         else
         {
             
             if([code hasPrefix:@"msauth://"])
             {
                 [self handleBrokerFromWebiewResponse:code
                                             resource:resource
                                             clientId:clientId
                                          redirectUri:redirectUri
                                               userId:userId
                                 extraQueryParameters:queryParams
                                        correlationId:correlationId
                                      completionBlock:completionBlock];
             }
             else
             {
                 [self requestTokenByCode:code
                                 resource:resource
                                 clientId:clientId
                              redirectUri:redirectUri
                                    scope:scope
                            correlationId:correlationId
                               completion:^(ADAuthenticationResult *result)
                  {
                      if (AD_SUCCEEDED == result.status)
                      {
                          [self updateCacheToResult:result cacheItem:nil withRefreshToken:nil];
                          result = [self updateResult:result toUser:userId];
                      }
                      completionBlock(result);
                  }];
             }
         }
     }];
}

#pragma mark -
#pragma mark Refresh Token
//Obtains an access token from the passed refresh token. If "cacheItem" is passed, updates it with the additional
//information and updates the cache:
- (void)internalAcquireTokenByRefreshToken:(NSString*)refreshToken
                                  clientId:(NSString*)clientId
                               redirectUri:(NSString*)redirectUri
                                  resource:(NSString*)resource
                                    userId:(ADUserIdentifier*)userId
                                 cacheItem:(ADTokenCacheStoreItem*)cacheItem
                         validateAuthority:(BOOL)validateAuthority
                             correlationId:(NSUUID*)correlationId
                           completionBlock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(refreshToken);
    HANDLE_ARGUMENT(clientId);
    
    AD_LOG_VERBOSE_F(@"Attempting to acquire an access token from refresh token.", @"Resource: %@", resource);
    
    [self updateCorrelationId:&correlationId];
    if (validateAuthority)
    {
        [[ADInstanceDiscovery sharedInstance] validateAuthority:self.authority correlationId:correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             if (error)
             {
                 completionBlock([ADAuthenticationResult resultFromError:error]);
             }
             else
             {
                 [self validatedAcquireTokenByRefreshToken:refreshToken
                                                  clientId:clientId
                                               redirectUri:redirectUri
                                                  resource:resource
                                                    userId:userId
                                                 cacheItem:cacheItem
                                             correlationId:correlationId
                                           completionBlock:completionBlock];
             }
         }];
        return;//The asynchronous block above will handle everything;
    }
    
    [self validatedAcquireTokenByRefreshToken:refreshToken
                                     clientId:clientId
                                  redirectUri:redirectUri
                                     resource:resource
                                       userId:userId
                                    cacheItem:cacheItem
                                correlationId:correlationId
                              completionBlock:completionBlock];
}

- (void) validatedAcquireTokenByRefreshToken:(NSString*) refreshToken
                                    clientId:(NSString*) clientId
                                 redirectUri:(NSString*) redirectUri
                                    resource:(NSString*) resource
                                      userId:(ADUserIdentifier*)userId
                                   cacheItem:(ADTokenCacheStoreItem*) cacheItem
                               correlationId:(NSUUID*)correlationId
                             completionBlock:(ADAuthenticationCallback)completionBlock
{
    [ADLogger logToken:refreshToken tokenType:@"refresh token" expiresOn:nil correlationId:nil];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = nil;
    
    if(cacheItem.sessionKey)
    {
        NSString* jwtToken = [self createAccessTokenRequestJWTUsingRT:cacheItem
                                                             resource:resource
                                                             clientId:clientId];
        request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        redirectUri, @"redirect_uri",
                        clientId, @"client_id",
                        @"2.0", @"windows_api_version",
                        @"urn:ietf:params:oauth:grant-type:jwt-bearer", OAUTH2_GRANT_TYPE,
                        jwtToken, @"request",
                        nil];
        
    }
    else
    {
        request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        OAUTH2_REFRESH_TOKEN, OAUTH2_GRANT_TYPE,
                        refreshToken, OAUTH2_REFRESH_TOKEN,
                        clientId, OAUTH2_CLIENT_ID,
                        nil];
    }
    
    //The clang analyzer has some issues with the logic inside adIsStringNilOrBlank, as it is defined in a category.
#ifndef __clang_analyzer__
    if (![NSString adIsStringNilOrBlank:resource])
#else
        if (resource && ![NSString adIsStringNilOrBlank:resource])
#endif
        {
            [request_data setObject:resource forKey:OAUTH2_RESOURCE];
        }
    
    AD_LOG_INFO_F(@"Sending request for refreshing token.", @"Client id: '%@'; resource: '%@';", clientId, resource);
    [self requestWithServer:self.authority
                requestData:request_data
       requestCorrelationId:correlationId
            handledPkeyAuth:NO
          additionalHeaders:nil
                 completion:^(NSDictionary *response)
     {
         ADTokenCacheStoreItem* resultItem = (cacheItem) ? cacheItem : [ADTokenCacheStoreItem new];
         
         //Always ensure that the cache item has all of these set, especially in the broad token case, where the passed item
         //may have empty "resource" property:
         resultItem.resource = resource;
         resultItem.clientId = clientId;
         resultItem.authority = self.authority;
         
         
         ADAuthenticationResult *result = [self processTokenResponse:response forItem:resultItem fromRefresh:YES requestCorrelationId:correlationId];
         if (cacheItem)//The request came from the cache item, update it:
         {
             [self updateCacheToResult:result
                             cacheItem:resultItem
                      withRefreshToken:refreshToken];
         }
         result = [self updateResult:result toUser:userId];//Verify the user (just in case)
         
         completionBlock(result);
     }];
}

-(NSString*) createAccessTokenRequestJWTUsingRT:(ADTokenCacheStoreItem*) cacheItem
                                       resource:(NSString*) resource
                                       clientId:(NSString*) clientId
{
    NSString* grantType = @"refresh_token";
    
    NSString* ctx = [[[NSUUID UUID] UUIDString] adComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"typ" : @"JWT",
                             @"ctx" : [ADHelpers convertBase64UrlStringToBase64NSString:[ctx adBase64UrlEncode]]
                             };
    
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"resource" : resource,
                              @"client_id" : clientId,
                              @"refresh_token" : cacheItem.refreshToken,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
                              @"grant_type" : grantType,
                              @"aud" : self.authority
                              };
    
    NSString* returnValue = [ADHelpers createSignedJWTUsingKeyDerivation:header
                                                                 payload:payload
                                                                 context:ctx
                                                            symmetricKey:cacheItem.sessionKey];
    return returnValue;
}

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
                  resource:(NSString *)resource
                  clientId:(NSString*)clientId
               redirectUri:(NSURL*)redirectUri
                     scope:(NSString*)scope
             correlationId:(NSUUID*)correlationId
                completion:(ADAuthenticationCallback)completionBlock
{
    HANDLE_ARGUMENT(code);
    HANDLE_ARGUMENT(correlationId);//Should be set by the caller
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", @"Requesting token by authorization code for resource: %@", resource);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         OAUTH2_AUTHORIZATION_CODE, OAUTH2_GRANT_TYPE,
                                         code, OAUTH2_CODE,
                                         clientId, OAUTH2_CLIENT_ID,
                                         [redirectUri absoluteString], OAUTH2_REDIRECT_URI,
                                         nil];
    if(![NSString adIsStringNilOrBlank:scope])
    {
        [request_data setValue:scope forKey:OAUTH2_SCOPE];
    }
    
    [self executeRequest:self.authority
             requestData:request_data
                resource:resource
                clientId:clientId
    requestCorrelationId:correlationId
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}


@end
