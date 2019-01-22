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
#import "XCTestCase+TextFieldTap.h"
#import "NSURL+MSIDExtensions.h"

@interface ADALiOSBrokerInvocationTests : ADALBaseiOSUITest

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
    NSString *appBundleId = [self.class.confProvider appInstallForConfiguration:@"broker"][@"app_bundle_id"];
    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [brokerApp terminate];
    [super tearDown];
}

- (void)testBasicBrokerLoginWithBlackforestAccount
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderBlackForest;
    configurationRequest.needsMultipleUsers = NO;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];

    // Do interactive login
    MSIDAutomationTestRequest *instanceAwareRequest = [self.class.confProvider defaultAppRequest];
    instanceAwareRequest.uiBehavior = @"force";
    instanceAwareRequest.loginHint = self.primaryAccount.account;
    instanceAwareRequest.legacyAccountIdentifier = self.primaryAccount.account;
    instanceAwareRequest.legacyAccountIdentifierType = @"optional_displayable";
    instanceAwareRequest.extraQueryParameters = @{@"instance_aware": @1};
    instanceAwareRequest.brokerEnabled = YES;
    instanceAwareRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:self.class.confProvider.wwEnvironment];
    
    NSDictionary *instanceAwareConfig = [self configWithTestRequest:instanceAwareRequest];
    [self acquireToken:instanceAwareConfig];

    XCUIApplication *brokerApp = [self brokerApp];
    [self blackForestWaitForNextButton:brokerApp];
    
    [self enterPassword:self.primaryAccount.password app:brokerApp];
    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    NSString *issuer = [self resultIDTokenClaims][@"iss"];
    XCTAssertNotNil(issuer);
    NSString *issuerHost = [[NSURL URLWithString:issuer] msidHostWithPortIfNecessary];
    XCTAssertEqualObjects(issuerHost, @"sts.microsoftonline.de");
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // First try silent with WW authority
    [self acquireTokenSilent:instanceAwareConfig];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];

    // Now try silent with correct authority - #296889
    instanceAwareRequest.configurationAuthority = [NSString stringWithFormat:@"https://%@/common", self.testConfiguration.authorityHost];
    instanceAwareConfig = [self configWithTestRequest:instanceAwareRequest];
    [self acquireTokenSilent:instanceAwareConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:instanceAwareConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:instanceAwareConfig];
    [self assertAccessTokenNotNil];
}

- (void)testAppTerminationDuringBrokeredLogin
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"auto";
    request.loginHint = self.primaryAccount.account;
    request.brokerEnabled = YES;
    request.legacyAccountIdentifierType = self.primaryAccount.account;

    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    XCUIApplication *brokerApp = [self brokerApp];

    // Kill the test app
    [self.testApp terminate];

    [self enterPassword:self.primaryAccount.password app:brokerApp];

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
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    // Register device with this account
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp launch];
    [self.testApp activate];

    // Acquire token for a resource requiring device authentication
    MSIDAutomationTestRequest *deviceAuthRequest = [self.class.confProvider defaultAppRequest];
    deviceAuthRequest.uiBehavior = @"always";
    deviceAuthRequest.brokerEnabled = NO;
    deviceAuthRequest.loginHint = self.primaryAccount.account;
    deviceAuthRequest.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"sfb_guid"];
    
    NSDictionary *deviceAuthConf = [self configWithTestRequest:deviceAuthRequest];
    [self acquireToken:deviceAuthConf];
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
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    // Register device with that account
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp activate];

    // Acquire token for a resource that doesn't require device authentication
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.brokerEnabled = NO;
    request.loginHint = self.primaryAccount.account;
    request.legacyAccountIdentifier = self.primaryAccount.account;
    request.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"aad_graph"];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh with a resouce requiring device auth
    request.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"sfb_guid"];
    NSDictionary *deviceAuthConfig = [self configWithTestRequest:request];
    [self acquireTokenSilent:deviceAuthConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testSilentClaimsOnTheTokenEndpoint
{
    // Load configuration
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    // Register device with that account
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp activate];
    
    // Acquire token for a resource that doesn't require device authentication
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.brokerEnabled = NO;
    request.loginHint = self.primaryAccount.account;
    request.legacyAccountIdentifier = self.primaryAccount.account;
    request.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"aad_graph"];
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];
    
    // Now pass device claims to test claims on token endpoint
    request.claims = @"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D";
    NSDictionary *deviceAuthConfig = [self configWithTestRequest:request];

    [self acquireTokenSilent:deviceAuthConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

@end
