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

#import "ADAuthenticationRequest.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADInstanceDiscovery.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheKey.h"

@implementation ADAuthenticationRequest (AcquireToken)

#pragma mark -
#pragma mark AcquireToken

- (void)acquireToken:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(_resource);
    [self ensureRequest];
    
    if (!_context.validateAuthority)
    {
        [self validatedAcquireToken:completionBlock];
        return;
    }
    
    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority
                                              correlationId:_correlationId
                                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         (void)validated;
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
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
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:_context.authority
                                                              resource:_resource
                                                              clientId:_clientId
                                                                 error:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:_correlationId];
        completionBlock(result);
        return;
    }
    
    if (![ADAuthenticationContext isForcedAuthorization:_promptBehavior] && [_context hasCacheStore])
    {
        //Cache should be used in this case:
        ADTokenCacheItem* cacheItem = [self findCacheItemWithKey:key
                                                          userId:_identifier
                                                           error:&error];
        if (!cacheItem && error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
            return;
        }
        
        if (cacheItem)
        {
            //Found a promising item in the cache, try using it:
            [self attemptToUseCacheItem:cacheItem completionBlock:completionBlock];
            return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
        }
        
        ADTokenCacheItem* familyItem = [self findFamilyItemForUser:_identifier error:&error];
        if (familyItem)
        {
            [self attemptToUseCacheItem:familyItem completionBlock:completionBlock];
            return;
        }
    }
    
    [self requestToken:completionBlock];
}

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheItem*)item
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(item);
    AD_REQUEST_CHECK_PROPERTY(_resource);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    
    [self ensureRequest];
    
    if (item.accessToken && !item.isExpired)
    {
        //Access token is good, just use it:
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:_correlationId];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheItem:item multiResourceRefreshToken:NO correlationId:_correlationId];
        completionBlock(result);
        return;
    }
    
    if ([NSString adIsStringNilOrBlank:item.refreshToken])
    {
        completionBlock([ADAuthenticationResult resultFromError:[ADAuthenticationError unexpectedInternalError:@"Attempting to use an item without refresh token." correlationId:_correlationId]
                                                  correlationId:_correlationId]);
        return;
    }
    
    //Now attempt to use the refresh token of the passed cache item:
    BOOL isMultiResourceRefreshToken = [item isMultiResourceRefreshToken];
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
         
         //Try other means of getting access token result:
         if (!isMultiResourceRefreshToken)//Try multi-resource refresh token if not currently trying it
         {
             ADTokenCacheKey* broadKey = [ADTokenCacheKey keyWithAuthority:_context.authority resource:nil clientId:_clientId error:nil];
             if (broadKey)
             {
                 ADAuthenticationError* error;
                 ADTokenCacheItem* broadItem = [self findCacheItemWithKey:broadKey userId:_identifier error:&error];
                 if (!broadItem && error)
                 {
                     completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
                     return;
                 }
                 
                 if (broadItem)
                 {
                     if (![broadItem isMultiResourceRefreshToken])
                     {
                         AD_LOG_WARN(@"Unexpected", _correlationId, @"Multi-resource refresh token expected here.");
                         //Recover (avoid infinite recursion):
                         completionBlock(result);
                         return;
                     }
                     
                     //Call recursively with the cache item containing a multi-resource refresh token:
                     [self attemptToUseCacheItem:broadItem
                                 completionBlock:completionBlock];
                     return;//The call above takes over, no more processing
                 }//broad item
             }//key
         }//!item.multiResourceRefreshToken
         
         //The refresh token attempt failed and no other suitable refresh token found
         //call acquireToken
         [self requestToken:completionBlock];
     }];//End of the refreshing token completion block, executed asynchronously.
}

- (void)requestToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];

    if (_silent && !_allowSilent)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown:
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_INPUT_NEEDED
                                               protocolCode:nil
                                               errorDetails:ADCredentialsNeeded
                                              correlationId:_correlationId];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:_correlationId];
        completionBlock(result);
        return;
    }

#if !AD_BROKER
    //call the broker.
    if([self canUseBroker])
    {
        [self callBroker:completionBlock];
        return;
    }
#endif
    
    __block BOOL silentRequest = _allowSilent;
    
// Get the code first:
    [self requestCode:^(NSString * code, ADAuthenticationError *error)
     {
         if (error)
         {
             if (silentRequest)
             {
                 _allowSilent = NO;
                 [self requestToken:completionBlock];
                 return;
             }
             
             ADAuthenticationResult* result = (AD_ERROR_USER_CANCEL == error.code) ? [ADAuthenticationResult resultFromCancellation:_correlationId]
             : [ADAuthenticationResult resultFromError:error correlationId:_correlationId];
             completionBlock(result);
         }
         else
         {
             if([code hasPrefix:@"msauth://"])
             {
                 [self handleBrokerFromWebiewResponse:code
                                      completionBlock:completionBlock];
             }
             else
             {
                 [self requestTokenByCode:code
                          completionBlock:^(ADAuthenticationResult *result)
                  {
                      if (AD_SUCCEEDED == result.status)
                      {
                          [self updateCacheToResult:result cacheItem:nil refreshToken:nil];
                          result = [ADAuthenticationContext updateResult:result toUser:_identifier];
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
                         cacheItem:(ADTokenCacheItem*)cacheItem
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_ARGUMENT(refreshToken);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    
    [self ensureRequest];
    
    AD_LOG_VERBOSE_F(@"Attempting to acquire an access token from refresh token.", _correlationId, @"Resource: %@", _resource);
    
    if (!_context.validateAuthority)
    {
        [self validatedAcquireTokenByRefreshToken:refreshToken
                                        cacheItem:cacheItem
                                  completionBlock:completionBlock];
        return;
    }
    
    [[ADInstanceDiscovery sharedInstance] validateAuthority:_context.authority correlationId:_correlationId completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         (void)validated;
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
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
                                   cacheItem:(ADTokenCacheItem*)cacheItem
                             completionBlock:(ADAuthenticationCallback)completionBlock
{
    [ADLogger logToken:refreshToken tokenType:@"refresh token" expiresOn:nil correlationId:_correlationId];
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
                        nil];
    }
    
    if (![NSString adIsStringNilOrBlank:_resource])
    {
        [request_data setObject:_resource forKey:OAUTH2_RESOURCE];
    }
    
    AD_LOG_INFO_F(@"Sending request for refreshing token.", _correlationId, @"Client id: '%@'; resource: '%@';", _clientId, _resource);
    [self requestWithServer:_context.authority
                requestData:request_data
            handledPkeyAuth:NO
          additionalHeaders:nil
                 completion:^(NSDictionary *response)
     {
         ADTokenCacheItem* resultItem = (cacheItem) ? cacheItem : [ADTokenCacheItem new];
         
         //Always ensure that the cache item has all of these set, especially in the broad token case, where the passed item
         //may have empty "resource" property:
         resultItem.resource = _resource;
         resultItem.clientId = _clientId;
         resultItem.authority = _context.authority;
         
         
         ADAuthenticationResult *result = [resultItem processTokenResponse:response fromRefresh:YES requestCorrelationId:_correlationId];
         if (cacheItem)//The request came from the cache item, update it:
         {
             [self updateCacheToResult:result
                             cacheItem:resultItem
                          refreshToken:refreshToken];
         }
         result = [ADAuthenticationContext updateResult:result toUser:_identifier];//Verify the user (just in case)
         //
         if (!cacheItem)
         {
             SAFE_ARC_RELEASE(resultItem);
         }
         completionBlock(result);
     }];
}

-(NSString*) createAccessTokenRequestJWTUsingRT:(ADTokenCacheItem*)cacheItem
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
                              @"resource" : _resource,
                              @"client_id" : _clientId,
                              @"refresh_token" : cacheItem.refreshToken,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
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
    HANDLE_ARGUMENT(code, _correlationId);
    [self ensureRequest];
    AD_LOG_VERBOSE_F(@"Requesting token from authorization code.", _correlationId, @"Requesting token by authorization code for resource: %@", _resource);
    
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         OAUTH2_AUTHORIZATION_CODE, OAUTH2_GRANT_TYPE,
                                         code, OAUTH2_CODE,
                                         _clientId, OAUTH2_CLIENT_ID,
                                         _redirectUri, OAUTH2_REDIRECT_URI,
                                         nil];
    if(![NSString adIsStringNilOrBlank:_scope])
    {
        [request_data setValue:_scope forKey:OAUTH2_SCOPE];
    }
    
    [self executeRequest:_context.authority
             requestData:request_data
         handledPkeyAuth:NO
       additionalHeaders:nil
              completion:completionBlock];
}


@end
