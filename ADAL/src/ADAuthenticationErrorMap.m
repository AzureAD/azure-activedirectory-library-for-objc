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
        MSIDErrorDomain: ADAuthenticationErrorDomain,
        MSIDOAuthErrorDomain: ADOAuthServerErrorDomain,
        MSIDKeychainErrorDomain: ADKeychainErrorDomain,
        MSIDHttpErrorCodeDomain: ADHTTPErrorCodeDomain
    };

    s_errorCodeMapping = @{
        ADAuthenticationErrorDomain: @{
            // General
            @(MSIDErrorInternal): @(AD_ERROR_UNEXPECTED),
            @(MSIDErrorInvalidInternalParameter): @(AD_ERROR_UNEXPECTED),
            @(MSIDErrorInvalidDeveloperParameter): @(AD_ERROR_DEVELOPER_INVALID_ARGUMENT),
            @(MSIDErrorMissingAccountParameter): @(AD_ERROR_DEVELOPER_INVALID_ARGUMENT),
            @(MSIDErrorUnsupportedFunctionality): @(AD_ERROR_UNEXPECTED),
            @(MSIDErrorInteractionRequired): @(AD_ERROR_SERVER_USER_INPUT_NEEDED),
            @(MSIDErrorServerNonHttpsRedirect): @(AD_ERROR_SERVER_NON_HTTPS_REDIRECT),
            @(MSIDErrorMismatchedAccount): @(AD_ERROR_SERVER_WRONG_USER),
            // Cache
            @(MSIDErrorCacheMultipleUsers): @(AD_ERROR_CACHE_MULTIPLE_USERS),
            @(MSIDErrorCacheBadFormat): @(AD_ERROR_CACHE_BAD_FORMAT),
            // Authority Validation
            @(MSIDErrorAuthorityValidation): @(AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION),
            @(MSIDErrorAuthorityValidationWebFinger): @(AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION),
            // Interactive flow
            @(MSIDErrorUserCancel): @(AD_ERROR_UI_USER_CANCEL),
            @(MSIDErrorSessionCanceledProgrammatically): @(AD_ERROR_UI_USER_CANCEL),
            @(MSIDErrorInteractiveSessionStartFailure): @(AD_ERROR_UNEXPECTED),
            @(MSIDErrorInteractiveSessionAlreadyRunning): @(AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS),
            @(MSIDErrorNoMainViewController): @(AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER),
            @(MSIDErrorAttemptToOpenURLFromExtension): @(AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION),
            @(MSIDErrorUINotSupportedInExtension): @(AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION),
            // Broker flow
            @(MSIDErrorBrokerResponseNotReceived): @(AD_ERROR_TOKENBROKER_NOT_A_BROKER_RESPONSE),
            @(MSIDErrorBrokerNoResumeStateFound): @(AD_ERROR_TOKENBROKER_NO_RESUME_STATE),
            @(MSIDErrorBrokerBadResumeStateFound): @(AD_ERROR_TOKENBROKER_BAD_RESUME_STATE),
            @(MSIDErrorBrokerMismatchedResumeState): @(AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE),
            @(MSIDErrorBrokerResponseHashMissing): @(AD_ERROR_TOKENBROKER_HASH_MISSING),
            @(MSIDErrorBrokerCorruptedResponse): @(AD_ERROR_TOKENBROKER_NOT_A_BROKER_RESPONSE),
            @(MSIDErrorBrokerResponseDecryptionFailed): @(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED),
            @(MSIDErrorBrokerResponseHashMismatch): @(AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH),
            @(MSIDErrorBrokerKeyFailedToCreate): @(AD_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY),
            @(MSIDErrorBrokerKeyNotFound): @(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED),
            @(MSIDErrorWorkplaceJoinRequired): @(AD_ERROR_SERVER_WPJ_REQUIRED),
            @(MSIDErrorBrokerUnknown): @(AD_ERROR_TOKENBROKER_UNKNOWN)
        },
        ADOAuthServerErrorDomain: @{
            @(MSIDErrorServerOauth): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerInvalidResponse): @(AD_ERROR_SERVER_INVALID_RESPONSE),
            @(MSIDErrorServerRefreshTokenRejected): @(AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED),
            @(MSIDErrorServerInvalidRequest): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerInvalidClient): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerInvalidGrant): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerInvalidScope): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerUnauthorizedClient): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerDeclinedScopes): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerInvalidState): @(AD_ERROR_SERVER_OAUTH),
            @(MSIDErrorServerProtectionPoliciesRequired): @(AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED),
            @(MSIDErrorAuthorizationFailed): @(AD_ERROR_SERVER_AUTHORIZATION_CODE),
        },

        ADHTTPErrorCodeDomain: @{
            @(MSIDErrorServerUnhandledResponse): @(AD_ERROR_UNEXPECTED)
        }
    };

    s_userInfoKeyMapping = @{
        MSIDHTTPHeadersKey: ADHTTPHeadersKey,
        MSIDOAuthSubErrorKey: ADSuberrorKey,
        MSIDUserDisplayableIdkey: ADUserIdKey
    };
}

+ (NSErrorDomain)adErrorDomainFromMsidError:(NSError *)msidError
{
    if (!msidError) return nil;
    return s_errorDomainMapping[msidError.domain];
}

+ (NSInteger)adErrorCodeFromMsidError:(NSError *)msidError
{
    if (!msidError) return AD_ERROR_UNEXPECTED;
    
    NSString *adDomain = [self adErrorDomainFromMsidError:msidError];
    if (!adDomain) return msidError.code;
    
    NSNumber *mappedErrorCode = s_errorCodeMapping[adDomain][@(msidError.code)];
    if (!mappedErrorCode)
    {
        NSAssert(NO, @"Error mapping incorrect - domain found, but code no match.");
        MSID_LOG_WARN(nil, @"ADAuthenticationErrorMap - could not find the error code mapping entry for domain (%@) + error code (%ld).", adDomain, (long)msidError.code);
        return msidError.code;
    }
    
    return [mappedErrorCode integerValue];
}

@end
