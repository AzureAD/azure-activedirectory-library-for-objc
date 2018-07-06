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


#import "ADAcquireTokenSilentHandler.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADUserInformation.h"
#import "ADWebAuthRequest.h"
#import "ADHelpers.h"
#import "ADTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "ADTelemetryAPIEvent.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADTokenCacheItem+MSIDTokens.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDAccount.h"
#import "MSIDLegacySingleResourceToken.h"
#import "MSIDRefreshToken.h"
#import "ADResponseCacheHandler.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDAccountIdentifier.h"
#import "ADAuthenticationSettings.h"

@interface ADAcquireTokenSilentHandler()

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) MSIDAADV1Oauth2Factory *factory;

@end

@implementation ADAcquireTokenSilentHandler

+ (ADAcquireTokenSilentHandler *)requestWithParams:(ADRequestParameters *)requestParams
                                        tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
{
    ADAcquireTokenSilentHandler* handler = [ADAcquireTokenSilentHandler new];
    
    // As this is an internal class these properties should all be set by the
    // authentication request, which created copies of them.
    
    handler->_requestParams = requestParams;
    handler.tokenCache = tokenCache;
    handler.factory = [MSIDAADV1Oauth2Factory new];
    
    return handler;
}

- (void)getToken:(ADAuthenticationCallback)completionBlock
{
    [self getAccessToken:^(ADAuthenticationResult *result)
     {
         // Logic for returning extended lifetime token
         if ([_requestParams extendedLifetime] && [self isServerUnavailable:result] && _extendedLifetimeAccessTokenItem)
         {
             // give the stale token as result
             [[MSIDLogger sharedLogger] logToken:_extendedLifetimeAccessTokenItem.accessToken
                                       tokenType:@"AT (extended lifetime)"
                                   expiresOnDate:_extendedLifetimeAccessTokenItem.expiresOn
                                    additionaLog:@"Returning"
                                         context:_requestParams];
             
             ADTokenCacheItem *cacheItem = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:_extendedLifetimeAccessTokenItem];
             cacheItem.expiresOn = _extendedLifetimeAccessTokenItem.extendedExpireTime;
             
             result = [ADAuthenticationResult resultFromTokenCacheItem:cacheItem
                                             multiResourceRefreshToken:NO
                                                         correlationId:[_requestParams correlationId]];
             [result setExtendedLifeTimeToken:YES];
         }
         
         completionBlock(result);
     }];
}

#pragma mark -
#pragma mark Refresh Token Helper Methods

//Obtains an access token from the passed refresh token. If "cacheItem" is passed, updates it with the additional
//information and updates the cache:
- (void)acquireTokenByRefreshToken:(NSString *)refreshToken
                         cacheItem:(MSIDBaseToken<MSIDRefreshableToken> *)cacheItem
                  useOpenidConnect:(BOOL)useOpenidConnect
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    [[MSIDLogger sharedLogger] logToken:refreshToken
                              tokenType:@"RT"
                          expiresOnDate:nil
                           additionaLog:[NSString stringWithFormat:@"Attempting to acquire for %@ using", _requestParams.resource]
                                context:_requestParams];
    //Fill the data for the token refreshing:
    NSMutableDictionary *request_data = nil;

    request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        MSID_OAUTH2_REFRESH_TOKEN, MSID_OAUTH2_GRANT_TYPE,
                        refreshToken, MSID_OAUTH2_REFRESH_TOKEN,
                        [_requestParams clientId], MSID_OAUTH2_CLIENT_ID,
                        nil];
    
    request_data[MSID_OAUTH2_CLIENT_INFO] = @YES;
    
    if (![NSString msidIsStringNilOrBlank:[_requestParams resource]])
    {
        [request_data setObject:[_requestParams resource] forKey:MSID_OAUTH2_RESOURCE];
    }

    if (useOpenidConnect)
    {
        request_data[MSID_OAUTH2_SCOPE] = _requestParams.openidScopesString;
    }
    else
    {
        request_data[MSID_OAUTH2_SCOPE] = _requestParams.scopesString;
    }

    NSString *authority = _requestParams.cloudAuthority ? _requestParams.cloudAuthority : _requestParams.authority;

    ADWebAuthRequest* webReq =
    [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:[authority stringByAppendingString:MSID_OAUTH2_TOKEN_SUFFIX]]
                                  context:_requestParams];
    [webReq setRequestDictionary:request_data];
    
    MSID_LOG_INFO(nil, @"Attempting to acquire an access token from refresh token");
    MSID_LOG_INFO_PII(nil, @"Attempting to acquire an access token from refresh token clientId: '%@', resource: '%@'", _requestParams.clientId, _requestParams.resource);
    
    [webReq sendRequest:^(ADAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock([ADAuthenticationResult resultFromError:error]);
             [webReq invalidate];
             return;
         }
         
         NSError *msidError = nil;
         MSIDTokenResponse *tokenResponse = [self.factory tokenResponseFromJSON:response
                                                                   refreshToken:cacheItem
                                                                        context:nil
                                                                          error:&msidError];
         
         if (msidError)
         {
             completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:_requestParams.correlationId]);
             return;
         }
         
         ADAuthenticationResult *result = [ADResponseCacheHandler processAndCacheResponse:tokenResponse
                                                                         fromRefreshToken:cacheItem
                                                                                    cache:self.tokenCache
                                                                                   params:_requestParams];
         
         completionBlock(result);
         
         [webReq invalidate];
     }];
}

- (NSString*)createAccessTokenRequestJWTUsingRT:(ADTokenCacheItem*)cacheItem
{
    NSString* grantType = @"refresh_token";
    
    NSString* ctx = [[[NSUUID UUID] UUIDString] msidComputeSHA256];
    NSDictionary *header = @{
                             @"alg" : @"HS256",
                             @"typ" : @"JWT",
                             @"ctx" : [ADHelpers convertBase64UrlStringToBase64NSString:[ctx msidBase64UrlEncode]]
                             };
    
    NSInteger iat = round([[NSDate date] timeIntervalSince1970]);
    NSDictionary *payload = @{
                              @"resource" : [_requestParams resource],
                              @"client_id" : [_requestParams clientId],
                              @"refresh_token" : cacheItem.refreshToken,
                              @"iat" : [NSNumber numberWithInteger:iat],
                              @"nbf" : [NSNumber numberWithInteger:iat],
                              @"exp" : [NSNumber numberWithInteger:iat],
                              @"scope" : @"openid",
                              @"grant_type" : grantType,
                              @"aud" : [_requestParams authority]
                              };
    
    NSString* returnValue = [ADHelpers createSignedJWTUsingKeyDerivation:header
                                                                 payload:payload
                                                                 context:ctx
                                                            symmetricKey:cacheItem.sessionKey];
    return returnValue;
}

- (void)acquireTokenWithItem:(MSIDBaseToken<MSIDRefreshableToken> *)refreshToken
                 refreshType:(NSString *)refreshType
            useOpenidConnect:(BOOL)useOpenidConnect
             completionBlock:(ADAuthenticationCallback)completionBlock
                    fallback:(ADAuthenticationCallback)fallback
{
    [[MSIDTelemetry sharedInstance] startEvent:[_requestParams telemetryRequestId] eventName:MSID_TELEMETRY_EVENT_TOKEN_GRANT];
    [self acquireTokenByRefreshToken:refreshToken.refreshToken
                           cacheItem:refreshToken
                    useOpenidConnect:useOpenidConnect
                     completionBlock:^(ADAuthenticationResult *result)
     {
         ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:MSID_TELEMETRY_EVENT_TOKEN_GRANT
                                                                        context:_requestParams];
         [event setGrantType:MSID_TELEMETRY_VALUE_BY_REFRESH_TOKEN];
         [event setResultStatus:[result status]];
         [[MSIDTelemetry sharedInstance] stopEvent:[_requestParams telemetryRequestId] event:event];

         NSString* resultStatus = @"Succeded";
         
         if (result.status == AD_FAILED)
         {
             if (result.error.protocolCode)
             {
                 resultStatus = [NSString stringWithFormat:@"Failed (%@)", result.error.protocolCode];
             }
             else
             {
                 resultStatus = [NSString stringWithFormat:@"Failed (%@ %ld)", result.error.domain, (long)result.error.code];
             }
         }
         
         NSString* msg = nil;
         if (refreshType)
         {
             msg = [NSString stringWithFormat:@"Acquire Token with %@ Refresh Token %@.", refreshType, resultStatus];
         }
         else
         {
             msg = [NSString stringWithFormat:@"Acquire Token with Refresh Token %@.", resultStatus];
         }
         
         MSID_LOG_INFO(_requestParams, @"%@", msg);
         MSID_LOG_INFO_PII(_requestParams, @"%@ clientId: '%@', resource: '%@'", msg, _requestParams.clientId, _requestParams.resource);
         
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

- (void)getAccessToken:(ADAuthenticationCallback)completionBlock
{
    //All of these should be set before calling this method:
    THROW_ON_NIL_ARGUMENT(completionBlock);
    NSUUID* correlationId = [_requestParams correlationId];

    NSError *msidError = nil;

    MSIDLegacySingleResourceToken *item = [self.tokenCache getSingleResourceTokenForAccount:_requestParams.account
                                                                              configuration:_requestParams.msidConfig
                                                                                    context:_requestParams
                                                                                      error:&msidError];
    
    // If some error ocurred during the cache lookup then we need to fail out right away.
    if (msidError)
    {
        completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:correlationId]);
        return;
    }

    // If we didn't find an item at all there's a chance that we might be dealing with an "ADFS" user
    // and we need to check the unknown user ADFS token as well
    if (!item)
    {
        MSIDAccountIdentifier *account = [[MSIDAccountIdentifier alloc] initWithLegacyAccountId:@"" homeAccountId:nil];

        item = [self.tokenCache getSingleResourceTokenForAccount:account
                                                   configuration:_requestParams.msidConfig
                                                         context:_requestParams
                                                           error:&msidError];
        
        if (msidError)
        {
            completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:correlationId]);
            return;
        }

        // If we still don't have anything from the cache to use then we should try to see if we have an MRRT
        // that matches.
        if (!item)
        {
            [self tryMRRT:completionBlock];
            return;
        }
    }

    // If we have a good (non-expired) access token then return it right away
    if (item.accessToken && ![item isExpiredWithExpiryBuffer:[ADAuthenticationSettings sharedInstance].expirationBuffer])
    {
        [[MSIDLogger sharedLogger] logToken:item.accessToken
                                  tokenType:@"AT"
                              expiresOnDate:item.expiresOn
                               additionaLog:@"Returning"
                                    context:_requestParams];
        
        ADTokenCacheItem *adItem = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:item];
        
        ADAuthenticationResult* result =
        [ADAuthenticationResult resultFromTokenCacheItem:adItem
                               multiResourceRefreshToken:NO
                                           correlationId:correlationId];
        completionBlock(result);
        return;
    }

    // If the access token is good in terms of extended lifetime then store it for later use
    if (item.accessToken && item.isExtendedLifetimeValid)
    {
        _extendedLifetimeAccessTokenItem = item;
    }

    [self tryRT:item completionBlock:completionBlock];
}

- (void)tryRT:(MSIDLegacySingleResourceToken *)item completionBlock:(ADAuthenticationCallback)completionBlock
{
    if (!item.refreshToken)
    {
        if (!item.isExtendedLifetimeValid)
        {
            NSError *msidError = nil;

            BOOL result = [self.tokenCache removeAccessToken:item
                                                     context:_requestParams
                                                       error:&msidError];
            
            if (!result)
            {
                // If we failed to remove the item with an error, then return that error right away
                completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:[_requestParams correlationId]]);
                return;
            }
        }
        
        if (!item.idToken)
        {
            // If we don't have any id token in this token that means it came from an authority
            // that doesn't support MRRTs or FRTs either, so fail right now.
            completionBlock(nil);
            return;
        }
        [self tryMRRT:completionBlock];
        return;
    }
    
    [self acquireTokenWithItem:item
                   refreshType:nil
              useOpenidConnect:item.idToken != nil
               completionBlock:completionBlock
                      fallback:^(ADAuthenticationResult* result)
     {
         // If we had an individual RT associated with this item then we aren't
         // talking to AAD so there won't be an MRRT. End the silent flow immediately.
         completionBlock(result);
     }];
}

/*
 This method will try to find and use an MRRT, that matches the parameters of the authentication request.
 If it finds one marked with a family ID it will call tryFRT before attempting to use the MRRT.
 */
- (void)tryMRRT:(ADAuthenticationCallback)completionBlock
{
    // If we don't have an item yet see if we can pull one out of the cache
    if (!_mrrtItem)
    {
        NSError *msidError = nil;

        MSIDRefreshToken *refreshToken = [self.tokenCache getRefreshTokenWithAccount:_requestParams.account
                                                                            familyId:nil
                                                                       configuration:_requestParams.msidConfig
                                                                             context:_requestParams
                                                                               error:&msidError];
        
        _mrrtItem = refreshToken;
        
        if (!_mrrtItem && msidError)
        {
            completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:[_requestParams correlationId]]);
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
              useOpenidConnect:YES
               completionBlock:completionBlock
                      fallback:^(ADAuthenticationResult* result)
     {
         NSString* familyId = _mrrtItem.familyId;

         // Clear out the MRRT as it's not good anymore anyways
         _mrrtItem = nil;
         _mrrtResult = result;

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
        completionBlock(_mrrtResult);
        return;
    }
    _attemptedFRT = YES;
    
    NSError *msidError = nil;

    if (!familyId)
    {
        // Use default family ID if no familyID provided to preserve the previous ADAL functionality
        familyId = @"1";
    }

    MSIDRefreshToken *refreshToken = [self.tokenCache getRefreshTokenWithAccount:_requestParams.account
                                                                        familyId:familyId
                                                                   configuration:_requestParams.msidConfig
                                                                         context:_requestParams
                                                                           error:&msidError];
    
    if (!refreshToken && msidError)
    {
        completionBlock([ADAuthenticationResult resultFromMSIDError:msidError correlationId:[_requestParams correlationId]]);
        return;
    }
    
    if (!refreshToken)
    {
        if (_mrrtItem)
        {
            // If we still have an MRRT item retrieved in this request then attempt to use that.
            [self tryMRRT:completionBlock];
        }
        else
        {
            // Otherwise go to interactive auth
            completionBlock(_mrrtResult);
        }
        return;
    }
    
    [self acquireTokenWithItem:refreshToken
                   refreshType:@"Family"
              useOpenidConnect:YES
               completionBlock:completionBlock
                      fallback:^(ADAuthenticationResult *result)
     {
         (void)result;
         
         if (_mrrtItem)
         {
             // If we still have an MRRT item retrieved in this request then attempt to use that.
             [self tryMRRT:completionBlock];
             return;
         }
         
         completionBlock(_mrrtResult);
     }];
}

- (BOOL)isServerUnavailable:(ADAuthenticationResult *)result
{
    if (![[result.error domain] isEqualToString:ADHTTPErrorCodeDomain])
    {
        return NO;
    }
    
    return ([result.error code] >= 500 && [result.error code] <= 599);
}

@end
