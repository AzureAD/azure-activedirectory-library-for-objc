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

#import "ADALResponseCacheHandler.h"
#import "ADALAuthenticationResult+Internal.h"
#import "MSIDLegacySingleResourceToken.h"
#import "ADALTokenCacheItem+MSIDTokens.h"
#import "ADALAuthenticationContext+Internal.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDError.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDTokenResponse.h"
#import "MSIDAccountIdentifier.h"
#import "ADALAuthenticationErrorConverter.h"

@implementation ADALResponseCacheHandler

+ (ADALAuthenticationResult *)processAndCacheResponse:(MSIDTokenResponse *)response
                                   fromRefreshToken:(MSIDBaseToken<MSIDRefreshableToken> *)refreshToken
                                              cache:(MSIDLegacyTokenCacheAccessor *)cache
                                             params:(ADALRequestParameters *)requestParams
                                      configuration:(MSIDConfiguration *)configuration
                                       verifyUserId:(BOOL)verifyUserId
{
    NSError *msidError = nil;

    MSIDAADV1Oauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
    
    BOOL result = [factory verifyResponse:response
                         fromRefreshToken:refreshToken != nil
                                  context:requestParams
                                    error:&msidError];
    
    if (!result)
    {
        return [self handleError:msidError
                    fromResponse:response
                fromRefreshToken:refreshToken
                           cache:cache
                          params:requestParams];
    }
    
    result = [cache saveTokensWithConfiguration:configuration
                                       response:response
                                        context:requestParams
                                          error:&msidError];
    
    if (!result)
    {
        MSID_LOG_ERROR(nil, @"Failed to save tokens in cache, error code %ld, error domain %@, description %@", (long)msidError.code, msidError.domain, msidError.description);
        MSID_LOG_ERROR_PII(nil, @"Failed to save tokens in cache, error %@", msidError);
    }
    
    MSIDLegacySingleResourceToken *resultToken = [factory legacyTokenFromResponse:response configuration:configuration];
        
    ADALTokenCacheItem *adTokenCacheItem = [[ADALTokenCacheItem alloc] initWithLegacySingleResourceToken:resultToken];
    
    ADALAuthenticationResult *adResult = [ADALAuthenticationResult resultFromTokenCacheItem:adTokenCacheItem
                                                              multiResourceRefreshToken:response.isMultiResource
                                                                          correlationId:requestParams.correlationId];
    
    return [ADALAuthenticationContext updateResult:adResult toUser:[requestParams identifier] verifyUserId:verifyUserId]; //Verify the user
}

+ (ADALAuthenticationResult *)handleError:(NSError *)msidError
                           fromResponse:(MSIDTokenResponse *)response
                       fromRefreshToken:(MSIDBaseToken<MSIDRefreshableToken> *)refreshToken
                                  cache:(MSIDLegacyTokenCacheAccessor *)cache
                                 params:(ADALRequestParameters *)requestParams
{
    NSString *subError = [[msidError userInfo] objectForKey:MSIDOAuthSubErrorKey];
    if (response.oauthErrorCode == MSIDErrorServerInvalidGrant && refreshToken && (subError == nil || [subError caseInsensitiveCompare:@"consent_required"] != NSOrderedSame))
    {
        NSError *removeError = nil;

        BOOL result = [cache validateAndRemoveRefreshToken:refreshToken
                                                   context:requestParams
                                                     error:&removeError];

        if (!result)
        {
            MSID_LOG_WARN(requestParams, @"Failed removing refresh token");
            MSID_LOG_WARN_PII(requestParams, @"Failed removing refresh token for account %@, token %@", requestParams.account, refreshToken);
        }
    }
    else if ([msidError.domain isEqualToString:MSIDOAuthErrorDomain] && msidError.code == MSIDErrorServerProtectionPoliciesRequired)
    {
        NSString *legacyAccountId = [self legacyAccountIdWithRefreshToken:refreshToken
                                                                    cache:cache
                                                                   params:requestParams];

        if (legacyAccountId)
        {
            ADALAuthenticationError *adError = [ADALAuthenticationError errorFromExistingError:[ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:msidError]
                                                                             correlationID:requestParams.correlationId
                                                                        additionalUserInfo:@{ADUserIdKey : legacyAccountId}];
            return [ADALAuthenticationResult resultFromError:adError];
        }
    }

    return [ADALAuthenticationResult resultFromMSIDError:msidError correlationId:requestParams.correlationId];
}

+ (NSString *)legacyAccountIdWithRefreshToken:(MSIDBaseToken<MSIDRefreshableToken> *)refreshToken
                                        cache:(MSIDLegacyTokenCacheAccessor *)cache
                                       params:(ADALRequestParameters *)requestParams
{
    NSString *legacyAccountId = refreshToken.accountIdentifier.legacyAccountId;

    if (!legacyAccountId)
    {
        NSError *accountReadError = nil;
        MSIDAccount *account = [cache accountForIdentifier:refreshToken.accountIdentifier
                                                  familyId:refreshToken.familyId
                                             configuration:requestParams.msidConfig
                                                   context:requestParams
                                                     error:&accountReadError];

        if (!account)
        {
            MSID_LOG_WARN(requestParams, @"Couldn't find the account for refresh token, returning error without user_id");
            MSID_LOG_WARN(requestParams, @"Couldn't find the account for refresh token, returning error without user_id (home account id = %@)", refreshToken.accountIdentifier.homeAccountId);
        }
        else
        {
            legacyAccountId = account.accountIdentifier.legacyAccountId;
        }
    }

    return legacyAccountId;
}

@end
