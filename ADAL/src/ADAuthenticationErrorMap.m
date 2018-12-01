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

#import "ADAuthenticationErrorMap.h"
#import "ADErrorCodes.h"
#import "ADAuthenticationError.h"
#import "MSIDError.h"

static NSDictionary *s_errorDomainMapping;
static NSDictionary *s_errorCodeMapping;
static NSDictionary *s_userInfoKeyMapping;

@implementation ADAuthenticationErrorMap

+ (NSDictionary *)errorDomains
{
    return s_errorDomainMapping;
}

+ (NSDictionary *)errorCodes
{
    return s_errorCodeMapping;
}

+ (NSDictionary *)userInfoKeys
{
    return s_userInfoKeyMapping;
}

+ (void)initialize
{
    s_errorDomainMapping = @{
                             MSIDErrorDomain : ADAuthenticationErrorDomain,
                             MSIDOAuthErrorDomain : ADOAuthServerErrorDomain,
                             MSIDKeychainErrorDomain : ADKeychainErrorDomain,
                             MSIDHttpErrorCodeDomain : ADHTTPErrorCodeDomain
                             };
    
    s_errorCodeMapping = @{
                           ADAuthenticationErrorDomain:@{
                                   // General
                                   @(MSIDErrorInternal) : @(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInvalidInternalParameter) : @(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInvalidDeveloperParameter) :@(AD_ERROR_DEVELOPER_INVALID_ARGUMENT),
                                   @(MSIDErrorUnsupportedFunctionality): @(AD_ERROR_UNEXPECTED),
                                   // Cache
                                   @(MSIDErrorCacheMultipleUsers) : @(AD_ERROR_CACHE_MULTIPLE_USERS),
                                   @(MSIDErrorCacheBadFormat) : @(AD_ERROR_CACHE_BAD_FORMAT),
                                   // Authority Validation
                                   @(MSIDErrorAuthorityValidation) : @(AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION),
                                   // Interactive flow
                                   @(MSIDErrorUserCancel) : @(AD_ERROR_UI_USER_CANCEL),
                                   @(MSIDErrorSessionCanceledProgrammatically) : @(AD_ERROR_UI_USER_CANCEL),
                                   @(MSIDErrorInteractiveSessionStartFailure) : @(AD_ERROR_UNEXPECTED),
                                   @(MSIDErrorInteractiveSessionAlreadyRunning) : @(AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS),
                                   @(MSIDErrorNoMainViewController) : @(AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER)
                                   },
                           ADOAuthServerErrorDomain:@{
                                   @(MSIDErrorInteractionRequired) : @(AD_ERROR_SERVER_USER_INPUT_NEEDED),
                                   @(MSIDErrorServerOauth) : @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerInvalidResponse) : @(AD_ERROR_SERVER_INVALID_RESPONSE),
                                   @(MSIDErrorServerRefreshTokenRejected) : @(AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED),
                                   @(MSIDErrorServerInvalidRequest) :@(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerInvalidClient) : @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerInvalidGrant) : @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerInvalidScope) : @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerInvalidState) : @(AD_ERROR_SERVER_OAUTH),
                                   @(MSIDErrorServerNonHttpsRedirect) : @(AD_ERROR_SERVER_NON_HTTPS_REDIRECT),
                                   @(MSIDErrorServerProtectionPoliciesRequired) : @(AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED),
                                   @(MSIDErrorAuthorizationFailed): @(AD_ERROR_SERVER_AUTHORIZATION_CODE)
                                   },
                           ADHTTPErrorCodeDomain: @{
                                   @(MSIDErrorServerUnhandledResponse) : @(AD_ERROR_UNEXPECTED)
                                   }
                           };
    
    s_userInfoKeyMapping = @{
                             MSIDHTTPHeadersKey : ADHTTPHeadersKey,
                             MSIDOAuthSubErrorKey : ADSuberrorKey
                             };
}


+ (NSErrorDomain)adErrorDomainFromMsidError:(NSError *)msidError
{
    if (!msidError) return nil;
    NSString *newDomain = s_errorDomainMapping[msidError.domain];
    
    return newDomain;
}

+ (NSInteger)adErrorCodeFromMsidError:(NSError *)msidError
{
    if (!msidError) return AD_ERROR_UNEXPECTED;
    
    NSString *adDomain = [self adErrorDomainFromMsidError:msidError];
    if (!adDomain) return msidError.code;
    
    
    NSNumber *mappedErrorCode = s_errorCodeMapping[adDomain][@(msidError.code)];
    if (!mappedErrorCode)
    {
        MSID_LOG_WARN(nil, @"ADAuthenticationErrorMap could not find the error code mapping entry for domain (%@) + error code (%ld).", adDomain, (long)msidError.code);
        return msidError.code;
    }
    
    return [mappedErrorCode integerValue];
}

@end
