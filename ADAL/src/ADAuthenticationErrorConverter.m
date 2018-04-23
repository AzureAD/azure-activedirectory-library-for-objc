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

#import "ADAuthenticationErrorConverter.h"
#import "ADAuthenticationError.h"
#import "MSIDError.h"

static NSDictionary *s_errorDomainMapping;
static NSDictionary *s_errorCodeMapping;
static NSDictionary *s_userInfoKeyMapping;

@interface ADAuthenticationError (ErrorConverterUtil)
+ (ADAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo;
@end

@implementation ADAuthenticationErrorConverter

+ (void)initialize
{
    s_errorDomainMapping = @{
                             MSIDErrorDomain : ADAuthenticationErrorDomain
                             };
    
    s_errorCodeMapping = @{
                           MSIDErrorDomain:@{
                                   @(MSIDErrorInternal):@(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInvalidInternalParameter):@(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInvalidDeveloperParameter):@(AD_ERROR_DEVELOPER_INVALID_ARGUMENT),
                                   @(MSIDErrorAmbiguousAuthority): @(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInteractionRequired):@(AD_ERROR_SERVER_USER_INPUT_NEEDED),
                                   @(MSIDErrorCacheMultipleUsers):@(AD_ERROR_CACHE_MULTIPLE_USERS),
                                   @(MSIDErrorTokenCacheItemFailure):@(AD_ERROR_CACHE_BAD_FORMAT),
                                   @(MSIDErrorWrapperCacheFailure): @(AD_ERROR_CACHE_BAD_FORMAT),
                                   @(MSIDErrorCacheBadFormat): @(AD_ERROR_CACHE_BAD_FORMAT),
                                   @(MSIDErrorCacheVersionMismatch): @(AD_ERROR_CACHE_VERSION_MISMATCH),
                                   @(MSIDErrorServerInvalidResponse):@(AD_ERROR_SERVER_INVALID_RESPONSE),
                                   @(MSIDErrorServerRefreshTokenRejected):@(AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED),
                                   @(MSIDErrorServerOauth): @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorInvalidRequest): @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorInvalidClient): @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorInvalidGrant): @(AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED),
                                   @(MSIDErrorInvalidParameter):@(AD_ERROR_DEVELOPER_INVALID_ARGUMENT),
                                   @(MSIDErrorDeveloperAuthorityValidation):@(AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION)
                                   }
                           };
    
    s_userInfoKeyMapping = @{MSIDHTTPHeadersKey : ADHTTPHeadersKey};
}

+ (ADAuthenticationError *)ADAuthenticationErrorFromMSIDError:(NSError *)msidError
{
    if (!msidError)
    {
        return nil;
    }
    
    // Map domain
    NSString *domain = msidError.domain;
    if (domain && s_errorDomainMapping[domain])
    {
        domain = s_errorDomainMapping[domain];
    }
    
    // Map errorCode
    // errorCode mapping is needed only if domain is in s_errorCodeMapping
    NSInteger errorCode = msidError.code;
    if (msidError.domain && msidError.code && s_errorCodeMapping[msidError.domain])
    {
        NSNumber *mappedErrorCode = s_errorCodeMapping[msidError.domain][@(msidError.code)];
        if (mappedErrorCode)
        {
            errorCode = [mappedErrorCode integerValue];
        }
        else
        {
            MSID_LOG_ERROR(nil, @"ADAuthenticationErrorConverter could not find the error code mapping entry for domain (%@) + error code (%ld).", msidError.domain, (long)msidError.code);
        }
    }
    
    NSMutableDictionary *userInfo = [NSMutableDictionary new];
    
    for (NSString *key in [msidError.userInfo allKeys])
    {
        NSString *mappedKey = s_userInfoKeyMapping[key] ? s_userInfoKeyMapping[key] : key;
        userInfo[mappedKey] = msidError.userInfo[key];
    }
    
    return [ADAuthenticationError errorWithDomainInternal:domain
                                                     code:errorCode
                                        protocolErrorCode:msidError.userInfo[MSIDOAuthErrorKey]
                                             errorDetails:msidError.userInfo[MSIDErrorDescriptionKey]
                                            correlationId:msidError.userInfo[MSIDCorrelationIdKey]
                                                 userInfo:userInfo];
}

@end
