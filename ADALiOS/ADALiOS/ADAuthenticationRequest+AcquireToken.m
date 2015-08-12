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

#import "ADAuthenticationRequest.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADInstanceDiscovery.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"

@implementation ADAuthenticationRequest (AcquireToken)

#pragma mark -
#pragma mark AcquireToken

- (void)acquireToken:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    if (![self validateProperties:completionBlock])
    {
        return;
    }
    
    if (!_context.validateAuthority)
    {
        [self validatedAcquireToken:completionBlock];
        return;
    }
    
    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority
                                              correlationId:_correlationId
                                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error]);
         }
         else
         {
             [self validatedAcquireToken:completionBlock];
         }
     }];

}

- (void)validatedAcquireToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    //Check the cache:
    ADAuthenticationError* error = nil;
    //We are explicitly creating a key first to ensure indirectly that all of the required arguments are correct.
    //This is the safest way to guarantee it, it will raise an error, if the the any argument is not correct:
    ADTokenCacheStoreKey* key = [self cacheStoreKey:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    if (![ADAuthenticationContext isForcedAuthorization:_promptBehavior] && [_context hasCacheStore])
    {
        //Cache should be used in this case:
        BOOL accessTokenUsable;
        ADTokenCacheStoreItem* cacheItem = [_context findCacheItemWithKey:key userId:_identifier useAccessToken:&accessTokenUsable error:&error];
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
                        completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
    }
    
    [self requestToken:completionBlock];
}

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheStoreItem*)item
               useAccessToken:(BOOL)useAccessToken
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(item);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    
    [self ensureRequest];
    
    if (useAccessToken && [item containsScopes:_scopes])
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:nil];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheStoreItem:item];
        completionBlock(result);
        return;
    }
    
    if ([NSString adIsStringNilOrBlank:item.refreshToken])
    {
        completionBlock([ADAuthenticationResult resultFromError:
                         [ADAuthenticationError unexpectedInternalError:@"Attempting to use an item without refresh token."]]);
        return;
    }
    
    //Now attempt to use the refresh token of the passed cache item:
    [self acquireTokenByRefreshToken:item.refreshToken
                           cacheItem:item
                     completionBlock:^(ADAuthenticationResult *result)
     {
         //Asynchronous block:
         if ([ADAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestToken:completionBlock];
     }];//End of the refreshing token completion block, executed asynchronously.
}


- (void)requestToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
#if !AD_BROKER
    if (_silent && !_allowSilent)
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

#if BROKER_ENABLED
    //call the broker.
    if([ADAuthenticationRequest canUseBroker])
    {
        [self callBroker:completionBlock];
        return;
    }
#endif
#endif
    
    //Get the code first:
    [self requestCode:^(NSString * code, ADAuthenticationError *error)
     {
         if (error)
         {
             ADAuthenticationResult* result = (AD_ERROR_USER_CANCEL == error.code) ? [ADAuthenticationResult resultFromCancellation]
             : [ADAuthenticationResult resultFromError:error];
             completionBlock(result);
         }
         else
         {
#if BROKER_ENABLED
             if([code hasPrefix:@"msauth://"])
             {
                 [self handleBrokerFromWebiewResponse:code
                                      completionBlock:completionBlock];
             }
             else
#endif // BROKER_ENABLED
             {
                 [self requestTokenByCode:code
                          completionBlock:^(ADAuthenticationResult *result)
                  {
                      if (AD_SUCCEEDED == result.status)
                      {
                          [_context updateCacheToResult:result cacheItem:nil withRefreshToken:nil];
                          result = [_context updateResult:result toUser:_identifier];
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
- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                         cacheItem:(ADTokenCacheStoreItem*)cacheItem
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(refreshToken);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    
    [self ensureRequest];
    
    AD_LOG_VERBOSE_F(@"Attempting to acquire an access token from refresh token.", @"scopes: %@", _scopes);
    
    if (!_context.validateAuthority)
    {
        [self validatedAcquireTokenByRefreshToken:refreshToken
                                        cacheItem:cacheItem
                                  completionBlock:completionBlock];
        return;
    }
    
    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority correlationId:_correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error]);
         }
         else
         {
             [self validatedAcquireTokenByRefreshToken:refreshToken
                                             cacheItem:cacheItem
                                       completionBlock:completionBlock];
         }
     }];
}

- (void) validatedAcquireTokenByRefreshToken:(NSString*)refreshToken
                                   cacheItem:(ADTokenCacheStoreItem*)cacheItem
                             completionBlock:(ADAuthenticationCallback)completionBlock
{
    [ADLogger logToken:refreshToken tokenType:@"refresh token" expiresOn:nil correlationId:nil];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = nil;
    
    [self ensureRequest];
    
    if(cacheItem.sessionKey)
    {
        NSString* jwtToken = [self createAccessTokenRequestJWTUsingRT:cacheItem];
        request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        _redirectUri, @"redirect_uri",
                        _clientId, @"client_id",
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
                        _clientId, OAUTH2_CLIENT_ID,
                        [_scopes adSpaceDeliminatedString], OAUTH2_SCOPE,
                        nil];
    }
    
    AD_LOG_INFO_F(@"Sending request for refreshing token.", @"Client id: '%@'; scopes: '%@';", _clientId, _scopes);
    [self requestWithServer:_context.authority
                requestData:request_data
            handledPkeyAuth:NO
          additionalHeaders:nil
                 completion:^(NSDictionary *response)
     {
         ADTokenCacheStoreItem* resultItem = (cacheItem) ? cacheItem : [ADTokenCacheStoreItem new];
         
         //Always ensure that the cache item has all of these set, especially in the broad token case, where the passed item
         //may have empty "resource" property:
         
         // TODO: add scopes to result
         
         resultItem.clientId = _clientId;
         resultItem.authority = _context.authority;
         
         ADAuthenticationResult *result = [_context processTokenResponse:response forItem:resultItem fromRefresh:YES requestCorrelationId:_correlationId];
         if (cacheItem)//The request came from the cache item, update it:
         {
             [_context updateCacheToResult:result
                                 cacheItem:resultItem
                          withRefreshToken:refreshToken];
         }
         result = [_context updateResult:result toUser:_identifier];//Verify the user (just in case)
         
         completionBlock(result);
     }];
}

- (NSString*)createAccessTokenRequestJWTUsingRT:(ADTokenCacheStoreItem*)cacheItem
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
                              @"client_id" : _clientId,
                              @"refresh_token" : cacheItem.refreshToken,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : [_scopes adSpaceDeliminatedString],
                              @"grant_type" : grantType,
                              @"aud" : _context.authority
                              };
    
    NSString* returnValue = [ADHelpers createSignedJWTUsingKeyDerivation:header
                                                                 payload:payload
                                                                 context:ctx
                                                            symmetricKey:cacheItem.sessionKey];
    return returnValue;
}

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString *)code
           completionBlock:(ADAuthenticationCallback)completionBlock
{
    HANDLE_ARGUMENT(code);
    [self ensureRequest];
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", @"Requesting token by authorization code for scopes: %@", _scopes);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         OAUTH2_AUTHORIZATION_CODE, OAUTH2_GRANT_TYPE,
                                         code, OAUTH2_CODE,
                                         _clientId, OAUTH2_CLIENT_ID,
                                         _redirectUri, OAUTH2_REDIRECT_URI,
                                         nil];
    
    [self executeRequest:_context.authority
             requestData:request_data
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}


@end
