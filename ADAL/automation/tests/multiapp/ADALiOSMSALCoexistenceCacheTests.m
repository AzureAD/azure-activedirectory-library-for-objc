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

@interface ADALiOSMSALCoexistenceCacheTests : ADALBaseiOSUITest

@end

@implementation ADALiOSMSALCoexistenceCacheTests

static BOOL msalAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead

    if (!msalAppInstalled)
    {
        msalAppInstalled = YES;
        [self installAppWithId:@"msal_unified"];
        [self.testApp activate];
        [self closeResultView];
    }

    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andSameClientId
{
    MSIDAutomationTestRequest *adalRequest = [self.class.confProvider defaultAppRequest];
    adalRequest.promptBehavior = @"always";
    adalRequest.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"ms_graph"];
    
    NSDictionary *adalConfig = [self configWithTestRequest:adalRequest];

    [self acquireToken:adalConfig];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    self.testApp = [self msalTestApp];
    
    MSIDAutomationTestRequest *msalRequest = [self.class.confProvider defaultAppRequest];
    msalRequest.requestScopes = [self.class.confProvider scopesForEnvironment:nil type:@"ms_graph"];
    msalRequest.homeAccountIdentifier = self.primaryAccount.homeAccountId;
    msalRequest.cacheAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil tenantId:self.primaryAccount.targetTenantId];
    msalRequest.redirectUri = [self.testConfiguration redirectUriWithPrefix:@"x-msauth-msalautomationapp"];
    
    NSDictionary *msalConfig = [self configWithTestRequest:msalRequest];
    
    // Acquire token silent
    [self acquireTokenSilent:msalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    [self expireAccessToken:msalConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do token refresh
    [self acquireTokenSilent:msalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirstAndUseDefaultScope_andSameClientId
{
    self.testApp = [self msalTestApp];
    
    MSIDAutomationTestRequest *msalRequest = [self.class.confProvider defaultAppRequest];
    msalRequest.requestScopes = [self.class.confProvider scopesForEnvironment:nil type:@"ms_graph"];
    msalRequest.homeAccountIdentifier = self.primaryAccount.homeAccountId;
    msalRequest.promptBehavior = @"force";
    msalRequest.redirectUri = [self.testConfiguration redirectUriWithPrefix:@"x-msauth-msalautomationapp"];
    
    NSDictionary *msalConfig = [self configWithTestRequest:msalRequest];
    [self acquireToken:msalConfig];
    [self acceptAuthSessionDialog];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    self.testApp = [XCUIApplication new];
    [self.testApp activate];
    
    MSIDAutomationTestRequest *adalRequest = [self.class.confProvider defaultAppRequest];
    adalRequest.promptBehavior = @"always";
    adalRequest.legacyAccountIdentifier = self.primaryAccount.account;
    adalRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *adalConfig = [self configWithTestRequest:adalRequest];

    // Acquire token silent
    [self acquireTokenSilent:adalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    [self expireAccessToken:adalConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do token refresh
    [self acquireTokenSilent:adalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    // Acquire token silent
    [self acquireTokenSilent:msalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andDifferentClient_withFociSupport
{
    // Foci is not support in MSAL yet
}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andDifferentClient_withFociSupport
{
    self.testApp = [self msalTestApp];
    
    MSIDAutomationTestRequest *msalRequest = [self.class.confProvider defaultFociRequestWithBroker];
    msalRequest.requestScopes = [self.class.confProvider scopesForEnvironment:nil type:@"aad_graph_static"];
    msalRequest.loginHint = self.primaryAccount.account;
    msalRequest.homeAccountIdentifier = self.primaryAccount.homeAccountId;
    msalRequest.promptBehavior = @"force";
    
    NSDictionary *msalConfig = [self configWithTestRequest:msalRequest];
    [self acquireToken:msalConfig];
    [self acceptAuthSessionDialog];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Switch back to the new ADAL app
    self.testApp = [XCUIApplication new];
    [self.testApp activate];
    
    MSIDAutomationTestRequest *adalRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    adalRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil tenantId:@"common"];
    adalRequest.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"aad_graph"];
    adalRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *adalConfig = [self configWithTestRequest:adalRequest];
    [self acquireTokenSilent:adalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];
    // Acquire token silent
    [self acquireTokenSilent:msalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithMSAL_whenSigninInADALWithBrokerFirst_andSameClientId
{
    [self removeAppWithId:@"broker"];
    [self.testApp activate];
    [self installAppWithId:@"broker"];
    [self allowNotificationsInSystemAlert];
    [self.testApp activate];
    [self closeResultView];
    
    MSIDAutomationTestRequest *adalRequest = [self.class.confProvider defaultAppRequest];
    adalRequest.brokerEnabled = YES;
    adalRequest.promptBehavior = @"auto";
    adalRequest.loginHint = self.primaryAccount.account;
    adalRequest.requestResource = [self.class.confProvider resourceForEnvironment:nil type:@"ms_graph"];
    
    NSDictionary *adalConfig = [self configWithTestRequest:adalRequest];
    [self acquireToken:adalConfig];

    XCUIApplication *brokerApp = [self brokerApp];

    [self enterPassword:self.primaryAccount.password app:brokerApp];
    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];
    
    MSIDAutomationTestRequest *msalRequest = [self.class.confProvider defaultAppRequest];
    msalRequest.legacyAccountIdentifier = self.primaryAccount.username;
    msalRequest.requestScopes = [self.class.confProvider scopesForEnvironment:nil type:@"ms_graph"];
    msalRequest.redirectUri = [self.testConfiguration redirectUriWithPrefix:@"x-msauth-msalautomationapp"];
    msalRequest.cacheAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil tenantId:self.primaryAccount.targetTenantId];
    
    NSDictionary *msalConfig = [self configWithTestRequest:msalRequest];

    // Acquire token silent
    [self acquireTokenSilent:msalConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (XCUIApplication *)msalTestApp
{
    NSDictionary *appConfiguration = [self.class.confProvider appInstallForConfiguration:@"msal_unified"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *msalApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [msalApp activate];
    BOOL result = [msalApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);
    return msalApp;
}

@end
