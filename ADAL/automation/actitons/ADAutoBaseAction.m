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

#import "ADAutoBaseAction.h"
#import "MSIDAutomationTestRequest.h"
#import "MSIDAutomationMainViewController.h"
#import "MSIDAutomation.h"
#import "MSIDAutomationErrorResult.h"
#import "MSIDAutomationSuccessResult.h"
#import <ADAL/ADAL.h>

#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#else
#import "ADTokenCache+Internal.h"
#endif

@implementation ADAutoBaseAction

- (NSString *)actionIdentifier
{
    return @"base_action";
}

- (BOOL)needsRequestParameters
{
    return NO;
}

- (void)performActionWithParameters:(MSIDAutomationTestRequest *)parameters
                containerController:(MSIDAutomationMainViewController *)containerController
                    completionBlock:(MSIDAutoCompletionBlock)completionBlock
{
    NSAssert(NO, @"Abstract class. Should be implemented in subclass");
}

#pragma mark - Helpers

- (ADAuthenticationContext *)contextFromParameters:(MSIDAutomationTestRequest *)request
                                             error:(NSError **)error
{
    NSError *applicationError = nil;
    ADAuthenticationContext *context = [[ADAuthenticationContext alloc] initWithAuthority:request.configurationAuthority
                                                                        validateAuthority:request.validateAuthority
                                                                                    error:&applicationError];

    if (!context)
    {
        return nil;
    }

    if (request.brokerEnabled)
    {
        context.credentialsType = AD_CREDENTIALS_AUTO;
    }
    else
    {
        context.credentialsType = AD_CREDENTIALS_EMBEDDED;
    }

    context.clientCapabilities = request.clientCapabilities;
    return context;
}

- (MSIDAutomationTestResult *)testResultWithADALError:(NSError *)error
{
    NSString *errorName = [ADAuthenticationError stringForADErrorCode:error.code];
    return [[MSIDAutomationErrorResult alloc] initWithAction:self.actionIdentifier
                                                       error:error
                                                   errorName:errorName
                                              additionalInfo:nil];
}

- (MSIDAutomationTestResult *)testResultWithADALResult:(ADAuthenticationResult *)adalResult
{
    if (adalResult.error)
    {
        return [self testResultWithADALError:adalResult.error];
    }

    MSIDAutomationUserInformation *userInfo = [MSIDAutomationUserInformation new];
    userInfo.objectId = adalResult.tokenCacheItem.userInformation.userObjectId;
    userInfo.tenantId = adalResult.tokenCacheItem.userInformation.tenantId;
    userInfo.givenName = adalResult.tokenCacheItem.userInformation.givenName;
    userInfo.familyName = adalResult.tokenCacheItem.userInformation.familyName;
    userInfo.username = adalResult.tokenCacheItem.userInformation.userId;
    userInfo.localAccountId = adalResult.tokenCacheItem.userInformation.uniqueId;

    NSURL *authority = [NSURL URLWithString:adalResult.tokenCacheItem.authority];
    userInfo.environment = authority.host;

    long expiresOn = [adalResult.tokenCacheItem.expiresOn timeIntervalSince1970];

    MSIDAutomationSuccessResult *result = [[MSIDAutomationSuccessResult alloc] initWithAction:self.actionIdentifier
                                                                                  accessToken:adalResult.tokenCacheItem.accessToken
                                                                                 refreshToken:adalResult.tokenCacheItem.refreshToken
                                                                                      idToken:adalResult.tokenCacheItem.userInformation.rawIdToken
                                                                                    authority:adalResult.authority
                                                                                       target:adalResult.tokenCacheItem.resource
                                                                                expiresOnDate:expiresOn
                                                                                       isMRRT:adalResult.tokenCacheItem.isMultiResourceRefreshToken
                                                                              userInformation:userInfo additionalInfo:nil];

    return result;
}

- (id<ADTokenCacheDataSource>)cacheDatasource
{
#if TARGET_OS_IPHONE
    return [ADKeychainTokenCache new];
#else
    return [ADTokenCache defaultCache];
#endif
}

- (ADPromptBehavior)promptBehaviorForRequest:(MSIDAutomationTestRequest *)request
{
    ADPromptBehavior promptBehavior = AD_PROMPT_AUTO;

    if (request.uiBehavior)
    {
        if ([request.uiBehavior isEqualToString:@"refresh_session"])
        {
            promptBehavior = AD_PROMPT_REFRESH_SESSION;
        }
        else if ([request.uiBehavior isEqualToString:@"always"])
        {
            promptBehavior = AD_PROMPT_ALWAYS;
        }
        else if ([request.uiBehavior isEqualToString:@"force"])
        {
            promptBehavior = AD_FORCE_PROMPT;
        }
    }

    return promptBehavior;
}

- (ADUserIdentifier *)userIdentifierForRequest:(MSIDAutomationTestRequest *)request
{
    NSString *userId = request.legacyAccountIdentifier;

    ADUserIdentifier *userIdentifier = nil;

    if (userId)
    {
        userIdentifier = [ADUserIdentifier identifierWithId:userId];
        NSString *userIdType = request.legacyAccountIdentifierType;

        if ([[userIdType lowercaseString] isEqualToString:@"unique_id"])
        {
            userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                 typeFromString:@"UniqueId"];
        }
        else if ([[userIdType lowercaseString] isEqualToString:@"optional_displayable"])
        {
            userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                 typeFromString:@"OptionalDisplayableId"];
        }
        else if ([[userIdType lowercaseString] isEqualToString:@"required_displayable"])
        {
            userIdentifier = [ADUserIdentifier identifierWithId:userId
                                                 typeFromString:@"RequiredDisplayableId"];
        }
    }

    return userIdentifier;
}

- (NSString *)extraQueryParamsForRequest:(MSIDAutomationTestRequest *)request
{
    NSDictionary *paramsDict = request.extraQueryParameters;

    if (!paramsDict)
    {
        return nil;
    }

    NSString *output = @"";

    for (NSString *key in [paramsDict allKeys])
    {
        output = [output stringByAppendingFormat:@"%@=%@", key, paramsDict[key]];
    }

    return output;
}

@end
