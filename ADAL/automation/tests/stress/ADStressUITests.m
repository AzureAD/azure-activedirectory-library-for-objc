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

#import "ADALBaseUITest.h"
#import "NSDictionary+ADALiOSUITests.h"
#import "XCUIElement+CrossPlat.h"
#import "MSIDAutomationActionConstants.h"
#import "MSIDAutomationSuccessResult.h"

@interface ADStressUITests : ADALBaseUITest

@end

@implementation ADStressUITests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testStressRun_withEmptyCache
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    NSDictionary *config = [self configWithTestRequest:request];
    [self performAction:MSID_AUTO_EMPTY_STRESS_TEST_ACTION_IDENTIFIER withConfig:config];
    sleep(self.class.confProvider.stressTestInterval); // run stress test for the specified interval
}

/*
 TODO: This stress test really shouldn't go against PROD ESTS.
 */

- (void)testStressRun_withNonEmptyCache
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:request];
    
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    [self performAction:MSID_AUTO_NON_EMPTY_STRESS_TEST_ACTION_IDENTIFIER withConfig:config];
    sleep(self.class.confProvider.stressTestInterval); // run stress test for the specified interval
}

- (void)testStressRun_withInteractiveAndSilentPollingInBackground
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self performAction:MSID_AUTO_INTERACTIVE_STRESS_TEST_ACTION_IDENTIFIER withConfig:config];
    
    [self aadEnterEmail];
    [self aadEnterPassword];

    MSIDAutomationSuccessResult *successResult = [self automationSuccessResult];
    XCTAssertNotNil(successResult);
    [self closeResultView];
}

@end
