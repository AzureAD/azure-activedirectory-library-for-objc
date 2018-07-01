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
#import "XCTestCase+TextFieldTap.h"
#import "NSURL+MSIDExtensions.h"

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
        [self removeAppWithId:@"broker"];
        [self.testApp activate];
        [self installAppWithId:@"broker"];
        [self allowNotificationsInSystemAlert];
        [self.testApp activate];
        [self closeResultView];
    }
}

- (void)tearDown
{
    NSString *appBundleId = [self.class.accountsProvider appInstallForConfiguration:@"broker"][@"app_bundle_id"];

    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [brokerApp terminate];
    [super tearDown];
}

- (void)testBasicBrokerLoginWithBlackforestAccount
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderBlackForest;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.needsMultipleUsers = NO;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];

    // Do interactive login
    NSDictionary *params = @{
                             @"prompt_behavior" : @"force",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"extra_qp": @"instance_aware=true",
                             @"authority" : @"https://login.microsoftonline.com/common",
                             @"use_broker": @YES
                             };
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];

    XCUIApplication *brokerApp = [self brokerApp];

    __auto_type nextButton = brokerApp.buttons[@"Next"];
    [self waitForElement:nextButton];
    [nextButton tap];

    XCUIElement *passwordTextField = brokerApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField app:brokerApp];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];

    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    NSString *issuer = [self resultIDTokenClaims][@"iss"];
    XCTAssertNotNil(issuer);
    NSString *issuerHost = [[NSURL URLWithString:issuer] msidHostWithPortIfNecessary];
    XCTAssertEqualObjects(issuerHost, @"sts.microsoftonline.de");
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // First try silent with WW authority
    NSDictionary *silentParams = @{
                                   @"user_identifier" : self.primaryAccount.account,
                                   @"client_id" : self.testConfiguration.clientId,
                                   @"resource" : self.testConfiguration.resource,
                                   @"authority" : @"https://login.microsoftonline.com/common"
                                   };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
    [self acquireTokenSilent:config];

    [self assertError:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];

    // Now try silent with correct authority - #296889
    silentParams = @{
                     @"user_identifier" : self.primaryAccount.account,
                     @"client_id" : self.testConfiguration.clientId,
                     @"authority" : self.testConfiguration.authority,
                     @"resource" : self.testConfiguration.resource
                     };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
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

    XCUIApplication *brokerApp = [self brokerApp];

    // Kill the test app
    [self.testApp terminate];

    [self aadEnterPasswordInApp:brokerApp];

    BOOL result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    // Now get access token
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
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

- (void)testDeviceAuthInInteractiveFlow
{
    // Load configuration
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    //configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    // Register device with this account
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp activate];

    // Acquire token for a resource requiring device authentication
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @NO,
                             @"resource": @"00000004-0000-0ff1-ce00-000000000000"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    [brokerApp terminate];
}

- (void)testDeviceAuthInSilentFlow
{
    // Load configuration
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    //configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    // Register device with that account
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp activate];

    // Acquire token for a resource that doesn't require device authentication
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @NO,
                             @"resource": @"00000002-0000-0000-c000-000000000000"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES,
               @"user_identifier" : self.primaryAccount.account,
               @"user_identifier_type" : @"optional_displayable",
               @"use_broker": @NO,
               @"resource": @"00000004-0000-0ff1-ce00-000000000000"
               };

    config = [self.testConfiguration configWithAdditionalConfiguration:params];

    // Now do access token refresh with a resouce requiring device auth
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

@end
