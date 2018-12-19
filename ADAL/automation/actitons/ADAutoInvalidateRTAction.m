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

#import "ADAutoInvalidateRTAction.h"
#import "MSIDAutomationActionConstants.h"
#import "MSIDAutomation.h"
#import "MSIDAutomationMainViewController.h"
#import "MSIDAutomationTestRequest.h"
#import "MSIDAutomationActionManager.h"
#import "MSIDAutomationTestResult.h"
#import "ADTokenCacheKey.h"

@implementation ADAutoInvalidateRTAction

+ (void)load
{
    [[MSIDAutomationActionManager sharedInstance] registerAction:[ADAutoInvalidateRTAction new]];
}

- (NSString *)actionIdentifier
{
    return MSID_AUTO_INVALIDATE_RT_ACTION_IDENTIFIER;
}

- (BOOL)needsRequestParameters
{
    return YES;
}

- (id<ADTokenCacheDataSource>)cacheDatasource
{
    return nil;
}

- (void)performActionWithParameters:(MSIDAutomationTestRequest *)parameters
                containerController:(MSIDAutomationMainViewController *)containerController
                    completionBlock:(MSIDAutoCompletionBlock)completionBlock
{
    id<ADTokenCacheDataSource> cache = [self cacheDatasource];

    NSMutableArray<ADTokenCacheItem *> *allItems = [NSMutableArray new];

    NSError *cacheError = nil;

    ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:parameters.cacheAuthority
                                                    resource:parameters.requestResource
                                                    clientId:parameters.clientId
                                                       error:&cacheError];

    NSArray *items = [cache getItemsWithKey:key
                                     userId:parameters.legacyAccountIdentifier
                              correlationId:nil
                                      error:&cacheError];

    if (!items)
    {
        MSIDAutomationTestResult *result = [self testResultWithADALError:cacheError];
        completionBlock(result);
        return;
    }

    int refreshTokenCount = 0;
    BOOL success = YES;

    for (ADTokenCacheItem *item in allItems)
    {
        if (item.refreshToken)
        {
            refreshTokenCount++;
            item.refreshToken = @"bad-refresh-token";
            success &= [cache addOrUpdateItem:item correlationId:nil error:nil];
        }
    }

    MSIDAutomationTestResult *result = [[MSIDAutomationTestResult alloc] initWithAction:self.actionIdentifier success:success additionalInfo:@{@"invalidated_refresh_token_count": @(refreshTokenCount)}];
    completionBlock(result);
}

@end
