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
    
    NSString* log = [NSString stringWithFormat:@"acquireToken (authority = %@, resource = %@, clientId = %@, idtype = %@)",
                     _context.authority, _resource, _clientId, [_identifier typeAsString]];
    AD_LOG_INFO_F(log, _correlationId, @"userId = %@", _identifier.userId);
    
    if (!_silent && ![NSThread isMainThread])
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_ON_MAIN_THREAD
                                               protocolCode:nil
                                               errorDetails:@"Interactive authentication requests must originate from the main thread"
                                              correlationId:_correlationId];
        
        completionBlock([ADAuthenticationResult resultFromError:error]);
        return;
    }
    
    if (!_silent && _context.credentialsType == AD_CREDENTIALS_AUTO && ![ADAuthenticationRequest validBrokerRedirectUri:_redirectUri])
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI
                                               protocolCode:nil
                                               errorDetails:ADRedirectUriInvalidError
                                              correlationId:_correlationId];
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
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
    
    if (![ADAuthenticationContext isForcedAuthorization:_promptBehavior] && [_context hasCacheStore])
    {
        [self findAccessToken:completionBlock];
        return;
    }
    
    [self requestToken:completionBlock];
}

- (void)acquireTokenWithItem:(ADTokenCacheItem *)item
                 refreshType:(NSString *)refreshType
             completionBlock:(ADAuthenticationCallback)completionBlock
                    fallback:(ADAuthenticationCallback)fallback
{
    [self acquireTokenByRefreshToken:item.refreshToken
                           cacheItem:item
                     completionBlock:^(ADAuthenticationResult *result)
     {
         NSString* msg = nil;
         if (refreshType)
         {
             msg = [NSString stringWithFormat:@"Acquire Token with %@ Refresh Token %@.", refreshType, result.status == AD_SUCCEEDED ? @"Succeeded" : @"Failed"];
         }
         else
         {
             msg = [NSString stringWithFormat:@"Acquire Token with Refresh Token %@.", result.status == AD_SUCCEEDED ? @"Succeeded" : @"Failed"];
         }
         
         AD_LOG_INFO_F(msg, _correlationId, @"clientId: '%@'; resource: '%@';", _clientId, _resource);
         
         if ([ADAuthenticationContext isFinalResult:result])
         {
             completionBlock(result);
             return;
         }
         
         fallback(result);
     }];
}

/*
    This is the beginning of the cache look up sequence. We start by trying to find an access token that is not
    expired. If there's a single-resource-refresh-token it will be cached along side an expire AT, and we'll
    attempt to use that. If not we fall into the MRRT<-->FRT code.
 */
 
- (void)findAccessToken:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    AD_REQUEST_CHECK_PROPERTY(_resource);
    AD_REQUEST_CHECK_PROPERTY(_clientId);
    
    [self ensureRequest];
    
    BOOL fADFSUser = NO;
    
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* item = [self getItemForResource:_resource clientId:_clientId error:&error];
    // If some error ocurred during the cache lookup then we need to fail out right away.
    if (!item && error)
    {
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
        return;
    }
    
    // If we didn't find an item at all there's a chance that we might be dealing with an "ADFS" user
    // and we need to check the unknown user ADFS token as well
    if (!item)
    {
        item = [self getUnkownUserADFSToken:&error];
        if (!item && error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
            return;
        }
        
        // If we still don't have anything from the cache to use then we should try to see if we have an MRRT
        // that matches.
        if (!item)
        {
            [self tryMRRT:completionBlock];
            return;
        }
        
        // If the token was an ADFS user then there's no reason to try any of the MRRT or FRT fallbacks
        fADFSUser = YES;
    }
    
    // If we have a good (non-expired) access token then return it right away
    if (item.accessToken && !item.isExpired)
    {
        [ADLogger logToken:item.accessToken tokenType:@"access token" expiresOn:item.expiresOn correlationId:_correlationId];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheItem:item multiResourceRefreshToken:NO correlationId:_correlationId];
        completionBlock(result);
        return;
    }

    if (!item.refreshToken)
    {
        // There's nothing usable in this cache item, delete it.
        if (![[_context tokenCacheStore] removeItem:item error:&error] && error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
            return;
        }
        
        // If we're not a ADFS user try the MRRT
        if (!fADFSUser)
        {
            [self tryMRRT:completionBlock];
            return;
        }
        
        // Otherwise go straight to interactive auth
        [self requestToken:completionBlock];
        return;
    }
    
    [self acquireTokenWithItem:item
                   refreshType:nil
               completionBlock:completionBlock
                      fallback:^(ADAuthenticationResult* result)
    {
        (void)result;
        // If we had an individual RT associated with this item then we aren't
        // talking to AAD so there won't be an MRRT. Go straight to interactive
        // auth.
        [self requestToken:completionBlock];
    }];
}

/*
    This method will try to find and use an MRRT, that matches the parameters of the authentication request.
    If it finds one marked with a family ID it will call tryFRT before attempting to use the MRRT.
 */
- (void)tryMRRT:(ADAuthenticationCallback)completionBlock
{
    ADAuthenticationError* error = nil;
    
    // If we don't have an item yet see if we can pull one out of the cache
    if (!_mrrtItem)
    {
        _mrrtItem = [self getItemForResource:nil clientId:_clientId error:&error];
        if (!_mrrtItem && error)
        {
            completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
            return;
        }
    }
    
    // If we still don't have an item try to use a FRT
    if (!_mrrtItem)
    {
        [self tryFRT:nil completionBlock:completionBlock];
        return;
    }
    
    // If our MRRT is marked with an Family ID and we haven't tried a FRT yet
    // try that first
    if (_mrrtItem.familyId && !_attemptedFRT)
    {
        [self tryFRT:_mrrtItem.familyId completionBlock:completionBlock];
        return;
    }
    
    // Otherwise try the MRRT
    [self acquireTokenWithItem:_mrrtItem
                   refreshType:@"Multi Resource"
               completionBlock:completionBlock
                      fallback:^(ADAuthenticationResult* result)
    {
         _underlyingError = result.error;
         SAFE_ARC_RETAIN(_underlyingError);
         
         NSString* familyId = _mrrtItem.familyId;
         
         // Clear out the MRRT as it's not good anymore anyways
         _mrrtItem = nil;
        
        // Try the FRT in case it's there.
         [self tryFRT:familyId completionBlock:completionBlock];
     }];
}

/*
    This method will attempt to find and use a FRT matching the given family ID and the parameters of the
    authentication request, if we've not already tried an FRT during this request. If it fails it will call
    -tryMRRT: If we have already tried to use an FRT then we go to interactive auth.
 */
 
- (void)tryFRT:(NSString*)familyId completionBlock:(ADAuthenticationCallback)completionBlock
{
    if (_attemptedFRT)
    {
        [self requestToken:completionBlock];
        return;
    }
    _attemptedFRT = YES;
    
    ADAuthenticationError* error = nil;
    NSString* familyClientId = [ADAuthenticationRequest familyClientId:familyId];
    
    ADTokenCacheItem* frtItem = [self getItemForResource:nil clientId:familyClientId error:&error];
    if (!frtItem && error)
    {
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
        return;
    }
    
    if (!frtItem)
    {
        if (_mrrtItem)
        {
            // If we still have an MRRT item retrieved in this request then attempt to use that.
            [self tryMRRT:completionBlock];
        }
        else
        {
            // Otherwise go to interactive auth
            [self requestToken:completionBlock];
        }
        return;
    }
    
    [self acquireTokenWithItem:frtItem refreshType:@"Family" completionBlock:completionBlock fallback:^(ADAuthenticationResult *result)
    {
        (void)result;
        
        if (_mrrtItem)
        {
            // If we still have an MRRT item retrieved in this request then attempt to use that.
            [self tryMRRT:completionBlock];
            return;
        }
        
        [self requestToken:completionBlock];
    }];
}

- (void)requestToken:(ADAuthenticationCallback)completionBlock
{
    [self ensureRequest];
    
    if (_samlAssertion)
    {
        [self requestTokenByAssertion:completionBlock];
        return;
    }

    if (_silent && !_allowSilent)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are needed to get an access token, but the developer, requested
        //no UI to be shown:
        NSDictionary* underlyingError = _underlyingError ? @{NSUnderlyingErrorKey:_underlyingError} : nil;
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_USER_INPUT_NEEDED
                                               protocolCode:nil
                                               errorDetails:ADCredentialsNeeded
                                                   userInfo:underlyingError
                                              correlationId:_correlationId];
        
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error correlationId:_correlationId];
        completionBlock(result);
        return;
    }
    
    //can't pop UI or go to broker in an extension
    if ([[[NSBundle mainBundle] bundlePath] hasSuffix:@".appex"]) {
        // this is an app extension
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION
                                               protocolCode:nil
                                               errorDetails:ADInteractionNotSupportedInExtension
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
             
             ADAuthenticationResult* result = (AD_ERROR_UI_USER_CANCEL == error.code) ? [ADAuthenticationResult resultFromCancellation:_correlationId]
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
    
    AD_LOG_INFO_F(@"Attempting to acquire an access token from refresh token", nil, @"clientId: '%@'; resource: '%@';", _clientId, _resource);
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
