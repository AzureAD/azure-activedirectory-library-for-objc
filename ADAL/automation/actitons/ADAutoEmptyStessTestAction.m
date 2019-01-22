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

#import "ADAutoEmptyStessTestAction.h"
#import "MSIDAutomationActionConstants.h"
#import "MSIDAutomation.h"
#import "MSIDAutomationMainViewController.h"
#import "MSIDAutomationTestRequest.h"
#import "MSIDAutomationActionManager.h"
#import "MSIDAutomationTestResult.h"

@implementation ADAutoEmptyStessTestAction

+ (void)load
{
    [[MSIDAutomationActionManager sharedInstance] registerAction:[ADAutoEmptyStessTestAction new]];
}

- (NSString *)actionIdentifier
{
    return MSID_AUTO_EMPTY_STRESS_TEST_ACTION_IDENTIFIER;
}

- (BOOL)needsRequestParameters
{
    return YES;
}

- (void)performActionWithParameters:(MSIDAutomationTestRequest *)parameters
                containerController:(MSIDAutomationMainViewController *)containerController
                    completionBlock:(MSIDAutoCompletionBlock)completionBlock
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        
        [self runStressTestImpl:parameters
                completionBlock:completionBlock];
        
    });
}

- (void)runStressTestImpl:(MSIDAutomationTestRequest *)parameters
          completionBlock:(MSIDAutoCompletionBlock)completionBlock
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(10);
    
    __block BOOL stop = NO;
    
    while (!stop)
    {
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            
            NSError *contextError = nil;
            ADAuthenticationContext *context = [self contextFromParameters:parameters error:&contextError];
            
            if (!context)
            {
                MSIDAutomationTestResult *result = [self testResultWithADALError:contextError];
                completionBlock(result);
                dispatch_semaphore_signal(sem);
                stop = YES;
                return;
            }
            
            [context acquireTokenSilentWithResource:parameters.requestResource
                                           clientId:parameters.clientId
                                        redirectUri:[NSURL URLWithString:parameters.redirectUri]
                                             userId:parameters.legacyAccountIdentifier
                                    completionBlock:^(ADAuthenticationResult *result) {
                                        dispatch_semaphore_signal(sem);
                                    }];
        });
    }
}

@end
