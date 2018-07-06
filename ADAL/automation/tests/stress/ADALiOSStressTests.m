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

@interface ADALiOSStressTests : ADALBaseUITest

@end

@implementation ADALiOSStressTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testStressRun_withEmptyCache
{
    [self runStressTestWithConfig:[self.testConfiguration config] testType:@"emptyCacheStressTest"];

    sleep(3600); // run stress test for one hour
}

- (void)testStressRun_withNonEmptyCache
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    [self runStressTestWithConfig:[self.testConfiguration config] testType:@"nonEmptyCacheStressTest"];

    sleep(3600); // run stress tests for one hour
}

- (void)testStressRun_withInteractiveAndSilentPollingInBackground
{
    NSDictionary *config = [self.testConfiguration config];
    [self runStressTestWithConfig:config testType:@"interactiveStressTest"];
    [self aadEnterEmail];
    [self aadEnterPassword];

    NSDictionary *result = [self resultDictionary];
    XCTAssertTrue([result[@"result"] boolValue]);
    [self closeResultView];
}

- (void)runStressTestWithConfig:(NSDictionary *)config testType:(NSString *)testType
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[testType] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidPasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] msidTap];
}

@end
