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

#import "ADAutoAcquireTokenAction.h"
#import "MSIDAutomationActionConstants.h"
#import "MSIDAutomation.h"
#import "MSIDAutomationMainViewController.h"
#import "MSIDAutomationTestRequest.h"
#import "MSIDAutomationActionManager.h"
#import "MSIDAutomationTestResult.h"
#import "MSIDAutomationPassedInWebViewController.h"
#import <ADAL/ADWebAuthController.h>

@implementation ADAutoAcquireTokenAction

+ (void)load
{
    [[MSIDAutomationActionManager sharedInstance] registerAction:[ADAutoAcquireTokenAction new]];
    
    [MSIDAutomationPassedInWebViewController setCancelTappedCallback:^{
        [ADWebAuthController cancelCurrentWebAuthSession];
    }];
}

- (NSString *)actionIdentifier
{
    return MSID_AUTO_ACQUIRE_TOKEN_ACTION_IDENTIFIER;
}

- (BOOL)needsRequestParameters
{
    return YES;
}

- (void)performActionWithParameters:(MSIDAutomationTestRequest *)request
                containerController:(MSIDAutomationMainViewController *)containerController
                    completionBlock:(MSIDAutoCompletionBlock)completionBlock
{

    NSError *applicationError = nil;
    ADAuthenticationContext *context = [self contextFromParameters:request error:&applicationError];

    if (!context)
    {
        MSIDAutomationTestResult *result = [self testResultWithADALError:applicationError];
        completionBlock(result);
        return;
    }

    if (request.usePassedWebView)
    {
        [containerController showPassedInWebViewControllerWithContext:@{@"context": context}];
        context.webView = containerController.passedinWebView;
    }

    ADPromptBehavior promptBehavior = [self promptBehaviorForRequest:request];
    ADUserIdentifier *userIdentifier = [self userIdentifierForRequest:request];

    NSString *extraQPString = [self extraQueryParamsForRequest:request];

    [context acquireTokenWithResource:request.requestResource
                             clientId:request.clientId
                          redirectUri:[NSURL URLWithString:request.redirectUri]
                       promptBehavior:promptBehavior
                       userIdentifier:userIdentifier
                 extraQueryParameters:extraQPString
                               claims:request.claims
                      completionBlock:^(ADAuthenticationResult *result)
     {
         dispatch_async(dispatch_get_main_queue(), ^{

             MSIDAutomationTestResult *testResult = [self testResultWithADALResult:result];
             completionBlock(testResult);
         });
     }];
}

@end
