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

@interface ADALiOSNonUnifiedADALCoexistenceCacheTests : ADALBaseiOSUITest

@end

@implementation ADALiOSNonUnifiedADALCoexistenceCacheTests

static BOOL adalAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead
    if (!adalAppInstalled)
    {
        adalAppInstalled = YES;
        [self installAppWithId:@"adal_n_minus_1_ver"];
        [self.testApp activate];
        [self closeResultView];
    }
    
    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

// #296895
- (void)testCoexistenceWithNonUnifiedADAL_startSigninInOlderADAL_withAADAccount_andDoTokenRefresh
{
    // Install previous ADAL version
    self.testApp = [self olderADALApp];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:request];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    NSDictionary *olderAppResult = [self automationResultDictionary];
    XCTAssertNotNil(olderAppResult[@"access_token"]);
    [self closeResultView];

    // Switch to the new ADAL version
    self.testApp = [XCUIApplication new];
    [self.testApp activate];

    // Acquire token silent
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithNonUnifiedADAL_startSigninInUnifiedADAL_withAADAccount_andDoTokenRefresh
{
    // Sign in the new test app
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Expire access token
    [self expireAccessToken:config];
    [self closeResultView];

    // Switch to the previous version
    self.testApp = [self olderADALApp];

    // Now do token refresh
    [self acquireTokenSilent:config];
    XCTAssertNotNil([self automationResultDictionary][@"access_token"]);
    [self closeResultView];
}

- (void)testCoexistenceWithNonUnifiedADAL_startSigninInNewADAL_withADFSOnPremAccount_andDoTokenRefresh
{
    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];

    // Sign into the current version
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.loginHint = self.primaryAccount.account;
    request.validateAuthority = NO;
    request.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Switch to the previous version
    self.testApp = [self olderADALApp];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    XCTAssertNotNil([self automationResultDictionary][@"access_token"]);
    [self closeResultView];

    // Switch back to the current version and do silent again
    self.testApp = [XCUIApplication new];
    [self.testApp activate];

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

- (void)testCoexistenceWithNonUnifiedADAL_startSigninInNewADAL_withAADAccount_andDoAuthorityMigration
{
    // Sign in the new test app
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"ww-alias"];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Switch to the previous version
    self.testApp = [self olderADALApp];
    
    MSIDAutomationTestRequest *aliasRequest = [self.class.confProvider defaultAppRequest];
    aliasRequest.promptBehavior = @"always";
    
    NSDictionary *aliasConfig = [self configWithTestRequest:aliasRequest];

    [self acquireTokenSilent:aliasConfig];
    XCTAssertNotNil([self automationResultDictionary][@"access_token"]);
    [self closeResultView];
}

- (void)testCoexistenceWithNonUnifiedADAL_startSigninInOlderADAL_withAADAccount_andUseFociToken
{
    self.testApp = [self olderADALApp];
    
    MSIDAutomationTestRequest *fociRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    fociRequest.promptBehavior = @"always";
    
    NSDictionary *fociConfig = [self configWithTestRequest:fociRequest];
    [self acquireToken:fociConfig];
    [self aadEnterEmail];
    [self aadEnterPassword];
    XCTAssertNotNil([self automationResultDictionary][@"access_token"]);
    [self closeResultView];

    // Switch back to the new ADAL app
    self.testApp = [XCUIApplication new];
    [self.testApp activate];
    
    MSIDAutomationTestRequest *secondFociRequest = [self.class.confProvider defaultFociRequestWithBroker];
    secondFociRequest.promptBehavior = @"always";
    
    NSDictionary *secondFociConfig = [self configWithTestRequest:secondFociRequest];
    [self acquireTokenSilent:secondFociConfig];
    [self assertAccessTokenNotNil];
}

- (XCUIApplication *)olderADALApp
{
    NSDictionary *appConfiguration = [self.class.confProvider appInstallForConfiguration:@"adal_n_minus_1_ver"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *olderApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [olderApp activate];
    BOOL result = [olderApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);
    return olderApp;
}

#pragma mark - Private

- (void)enterADFSPassword
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
