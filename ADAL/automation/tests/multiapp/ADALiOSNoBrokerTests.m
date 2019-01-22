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

#import "ADALBaseiOSUITest.h"

@interface ADALiOSNoBrokerTests : ADALBaseiOSUITest

@property (nonatomic) id interruptionMonitor;


@end

@implementation ADALiOSNoBrokerTests

- (void)setUp
{
    [super setUp];
    [self removeAppWithId:@"broker"];

    [self.testApp activate];
    
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

- (void)tearDown
{
    [super tearDown];
    [self removeAppWithId:@"broker"];
}

// #296886
- (void)testFirstTimeAuthenticatorInstallPrompt
{
    // Pre-open Authenticator app install URL
    [self openAppInstallURLForAppId:@"broker"];

    // Activate test app
    [self.testApp activate];
    [self.testApp.buttons[@"Done"] tap];

    // Load configuration
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.brokerEnabled = YES;
    request.loginHint = self.primaryAccount.account;
    request.legacyAccountIdentifier = self.primaryAccount.account;
    request.promptBehavior = @"always";
    request.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"sfb_guid"];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];

    // After user enters credentials, we should see Get the app button
    __auto_type registerButton = self.testApp.buttons[@"Get the app"];
    [self waitForElement:registerButton];
    [registerButton tap];

    // It should redirect to the app store install URL
    XCUIApplication *appStore = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.MobileStore"];
    BOOL result = [appStore waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    __auto_type appTitle = appStore.otherElements[@"Microsoft Authenticator "];
    [self waitForElement:appTitle];

    // Install broker app
    XCUIApplication *brokerApp = [self installAppWithIdWithSafariOpen:@"broker"];

    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    __auto_type allowButton = [springBoardApp.alerts.buttons elementBoundByIndex:0];
    [self waitForElement:allowButton];
    [allowButton tap];

    // Enter password in broker
    [self enterPassword:self.primaryAccount.password app:brokerApp];

    // It should prompt to register
    __auto_type registerButtonInBroker = brokerApp.buttons[@"Register"];
    [self waitForElement:registerButtonInBroker];
    [registerButtonInBroker tap];

    result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    // Register and wait for the token to be returned
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

// #296279
- (void)testBrokerInstallAfterInitialSignin
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"auto";
    request.brokerEnabled = YES;
    request.loginHint = self.primaryAccount.account;
    request.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    XCUIApplication *brokerApp = [self installAppWithId:@"broker"];
    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    __auto_type allowButton = [springBoardApp.alerts.buttons elementBoundByIndex:0];
    [self waitForElement:allowButton];
    [allowButton tap];

    [self.testApp activate];
    [self closeResultView];

    // Acquire token again to ensure broker is not called
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now invalidate refresh token
    [self invalidateRefreshToken:config];
    [self assertRefreshTokenInvalidated];
    [self closeResultView];

    // Make sure broker is used, since our local cache is now invalid
    [self acquireToken:config];
    BOOL result = [brokerApp waitForState:XCUIApplicationStateRunningForeground timeout:300.0f];
    XCTAssertTrue(result);

    if ([brokerApp.alerts.buttons[@"Ok"] exists])
    {
        [brokerApp.alerts.buttons[@"Ok"] tap];
    }

    [self enterPassword:self.primaryAccount.password app:brokerApp];
    result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// #test 296735
- (void)testBasicBrokerLoginAndAuthenticatorRemoval
{
    [self installAppWithId:@"broker"];
    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    __auto_type allowButton = [springBoardApp.alerts.buttons elementBoundByIndex:0];
    [self waitForElement:allowButton];
    [allowButton tap];

    [self.testApp activate];
    [self closeResultView];
    
    MSIDAutomationTestRequest *brokerRequest = [self.class.confProvider defaultAppRequest];
    brokerRequest.promptBehavior = @"auto";
    brokerRequest.brokerEnabled = YES;
    brokerRequest.loginHint = self.primaryAccount.account;
    brokerRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:brokerRequest];
    [self acquireToken:config];

    XCUIApplication *brokerApp = [self brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];
    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now remove authenticator, test #296748
    [self removeAppWithId:@"broker"];
    [self.testApp activate];

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
