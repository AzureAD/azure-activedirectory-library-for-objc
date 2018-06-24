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

@interface ADALiOSBrokerInvocationTests : ADALBaseUITest

@end

@implementation ADALiOSBrokerInvocationTests

static BOOL brokerAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead
    if (!brokerAppInstalled)
    {
        brokerAppInstalled = YES;
        [self installAppWithId:@"broker"];

        XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
        __auto_type allowButton = springBoardApp.alerts.buttons[@"Allow"];
        [self waitForElement:allowButton];
        [allowButton tap];
    }

    [self clearKeychain];
    [self.testApp activate];
}

- (void)testBasicBrokerLoginAndAuthenticatorRemoval
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];

    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:@"broker"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    BOOL result = [brokerApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    [self aadEnterPasswordInApp:brokerApp];

    result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

- (void)testAppTerminationDuringBrokeredLogin
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];

    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:@"broker"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    BOOL result = [brokerApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    // Kill the test app
    [self.testApp terminate];

    [self aadEnterPasswordInApp:brokerApp];

    result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

@end
