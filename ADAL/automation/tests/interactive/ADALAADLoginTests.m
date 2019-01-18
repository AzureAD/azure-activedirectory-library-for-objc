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

#import <XCTest/XCTest.h>
#import "ADALBaseAADUITest.h"
#import "NSDictionary+ADALiOSUITests.h"
#import "XCTestCase+TextFieldTap.h"
#import "XCUIElement+CrossPlat.h"
#import "MSIDAutomationSuccessResult.h"

@interface ADALAADInteractiveLoginTests : ADALBaseAADUITest

@end

@implementation ADALAADInteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    // Load accounts
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 1
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView
{
    // Setup test params
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:request];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);

    // Now do silent #2967259
    request.legacyAccountIdentifier = userId;
    [self runSharedSilentAADLoginWithTestRequest:request];
    
    request.legacyAccountIdentifier = nil;

    // Now do silent #296725 without providing user ID
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testInteractiveAndSilentAADLogin_withPromptAlways_andClientCapabilities_noLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.clientCapabilities = @[@"cp1"];
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:request];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    // Now do silent
    request.legacyAccountIdentifier = userId;
    [self runSharedSilentAADLoginWithTestRequest:request];
}

#if TARGET_OS_IPHONE
- (void)testInteractiveAndSilentAADMFALogin_withPromptAlways_noLoginHint_ADALWebView
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMFAEnabled];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.requestResource = [self.class.confProvider resourceForEnvironment:self.class.confProvider.wwEnvironment type:@"ms_graph"];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    __auto_type mfaTitle = self.testApp.staticTexts[@"Approve sign in request"];
    [self waitForElement:mfaTitle];

    [[XCUIDevice sharedDevice] pressButton:XCUIDeviceButtonHome];

    sleep(5);

    [self.testApp activate];
    __auto_type signinButton = self.testApp.links[@"Sign in another way"];
    [signinButton msidTap];

    __auto_type verifyTitle = self.testApp.staticTexts[@"Verify your identity"];
    [self waitForElement:verifyTitle];
}
#endif

- (void)testInteractiveAADLogin_withPromptAlways_noLoginHint_ADALWebView_andAuthCanceled
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self closeAuthUI];
    [self assertErrorCode:@"AD_ERROR_UI_USER_CANCEL"];
}

// #290995 iteration 2
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.loginHint = self.primaryAccount.account;
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:request];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    [self runSharedAuthUIAppearsStepWithTestRequest:request];
}

// #290995 iteration 3
- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.loginHint = self.primaryAccount.account;
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:request];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    request.legacyAccountIdentifier = userId;
    NSDictionary *config = [self configWithTestRequest:request];
    
    // Acquire token again.
    [self acquireToken:config];
    
    // Wait for result immediately, no user action required.
    [self assertAccessTokenNotNil];
    [self runSharedResultAssertionWithTestRequest:request];
}

// #290995 iteration 4
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_PassedInWebView
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.loginHint = self.primaryAccount.account;
    request.usePassedWebView = YES;
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:request];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    NSDictionary *config = [self configWithTestRequest:request];
    
    // Acquire token again with passed in webview
    [self acquireToken:config];
    [self aadEnterPassword];
}

// #296277: FoCI: Acquire a token using an FRT
- (void)testAADLogin_withPromptAlways_noLoginHint_acquireTokenUsingFRT
{
    MSIDAutomationTestRequest *firstRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    firstRequest.uiBehavior = @"always";
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:firstRequest];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    MSIDAutomationTestRequest *secondRequest = [self.class.confProvider defaultFociRequestWithBroker];
    secondRequest.legacyAccountIdentifier = userId;
    secondRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    
    NSDictionary *silentFociConfig = [self configWithTestRequest:secondRequest];
    // Should be able to acquire token silently because of foci token
    [self acquireTokenSilent:silentFociConfig];
    userId = [self runSharedResultAssertionWithTestRequest:secondRequest];
    XCTAssertEqualObjects(userId, self.primaryAccount.account);
}

// #296755: FoCI : MRRT Fallback when FRT Fails
- (void)testAADLogin_withPromptAlways_noLoginHint_MRRTFallbackWhenFRTFails
{
    MSIDAutomationTestRequest *fociRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    fociRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    fociRequest.uiBehavior = @"always";
    
    NSString *userId = [self runSharedAADLoginWithTestRequest:fociRequest];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    
    // Expire access token
    fociRequest.legacyAccountIdentifier = userId;
    NSDictionary *accessTokenConfig = [self configWithTestRequest:fociRequest];
    [self expireAccessToken:accessTokenConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    // Invalidate foci refresh token
    MSIDAutomationTestRequest *invalidateRTRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    invalidateRTRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    invalidateRTRequest.clientId = @"foci-1";
    invalidateRTRequest.legacyAccountIdentifier = userId;
    
    NSDictionary *invalidateRTConfig = [self configWithTestRequest:invalidateRTRequest];
    [self invalidateRefreshToken:invalidateRTConfig];
    [self assertRefreshTokenInvalidated];
    [self closeResultView];
    
    // Run silent again
    [self runSharedSilentAADLoginWithTestRequest:fociRequest];
}


// #296753: Login Multiple Accounts
- (void)testAADLogin_withPromptAlways_LoginHint_loginMultipleAccounts
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);
    
    // User 1, interactive login.
    MSIDAutomationTestRequest *firstRequest = [self.class.confProvider defaultAppRequest];
    firstRequest.uiBehavior = @"always";
    firstRequest.loginHint = self.primaryAccount.account;
    
    NSString *firstUserId = [self runSharedAADLoginWithTestRequest:firstRequest];
    XCTAssertNotNil(firstUserId);
    XCTAssertEqualObjects(firstUserId, self.primaryAccount.account.lowercaseString);
    
    // User 2, interactive login.
    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];
    
    MSIDAutomationTestRequest *secondRequest = [self.class.confProvider defaultAppRequest];
    secondRequest.uiBehavior = @"always";
    secondRequest.loginHint = self.primaryAccount.account;
    
    NSString *secondUserId = [self runSharedAADLoginWithTestRequest:secondRequest];
    XCTAssertNotNil(secondUserId);
    XCTAssertEqualObjects(secondUserId, self.primaryAccount.account.lowercaseString);
    
    // User 1, silent login.
    self.primaryAccount = self.testConfiguration.accounts[0];
    firstRequest.legacyAccountIdentifier = firstUserId;
    [self runSharedSilentAADLoginWithTestRequest:firstRequest];
    
    // User 2, silent login.
    self.primaryAccount = self.testConfiguration.accounts[1];
    secondRequest.legacyAccountIdentifier = secondUserId;
    [self runSharedSilentAADLoginWithTestRequest:secondRequest];
}

// #296758: Different ADUserIdentifierType settings
- (void)testAADLogin_withPromptAlways_LoginHint_differentUserTypeSettings
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    [self loadTestConfiguration:configurationRequest];
    
    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    MSIDTestAccount *firstAccount = self.testConfiguration.accounts[0];
    MSIDTestAccount *secondaryAccount = self.testConfiguration.accounts[1];

    // Optional Displayable, change account
    MSIDAutomationTestRequest *optionalIdRequest = [self.class.confProvider defaultAppRequest];
    optionalIdRequest.uiBehavior = @"always";
    optionalIdRequest.loginHint = secondaryAccount.account;
    optionalIdRequest.legacyAccountIdentifierType = @"optional_displayable";
    
    NSDictionary *optionalIdConfig = [self configWithTestRequest:optionalIdRequest];
    [self acquireToken:optionalIdConfig];
    
    // Change account
    [self signInWithAnotherAccount];
    
    // Enter username and password for a different user
    [self aadEnterEmail];
    [self aadEnterPassword];

    // Should succeed
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    // Verify that correct account was returned
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    XCTAssertNotNil(result.userInformation.legacyAccountId);
    XCTAssertEqualObjects(result.userInformation.legacyAccountId, firstAccount.account.lowercaseString);
    
    [self closeResultView];

    // Required Displayable, change account
    MSIDAutomationTestRequest *requiredIdRequest = [self.class.confProvider defaultAppRequest];
    requiredIdRequest.uiBehavior = @"always";
    requiredIdRequest.loginHint = secondaryAccount.account;
    requiredIdRequest.legacyAccountIdentifierType = @"required_displayable";
    
    NSDictionary *requiredIdConfig = [self configWithTestRequest:requiredIdRequest];
    [self acquireToken:requiredIdConfig];
    
    // Change account
    [self signInWithAnotherAccount];
    
    // Enter username and password for a different user
    [self aadEnterEmail];
    [self aadEnterPassword];

    // Should fail
    [self assertErrorCode:@"AD_ERROR_SERVER_WRONG_USER"];
    [self closeResultView];
    
    // RequiredDisplayableId and not changing the user
    NSString *userId = [self runSharedAADLoginWithTestRequest:requiredIdRequest];
    XCTAssertNotNil(userId);
    XCTAssertEqualObjects(userId, secondaryAccount.account.lowercaseString);
}

// 296732: Company Portal Install Prompt
- (void)test_companyPortalInstallPrompt
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMDMEnabled];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.loginHint = self.primaryAccount.account;

    NSDictionary *config = [self configWithTestRequest:request];
    
    [self acquireToken:config];
    [self aadEnterPassword];

    XCUIElement *enrollButton = self.testApp.buttons[@"Enroll now"];
    [self waitForElement:enrollButton];
    [enrollButton msidTap];
#if TARGET_OS_IPHONE
    XCUIApplication *safari = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.mobilesafari"];
#else
    XCUIApplication *safari = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.Safari"];
#endif

    BOOL result = [safari waitForState:XCUIApplicationStateRunningForeground timeout:20];
    XCTAssertTrue(result);

#if TARGET_OS_IPHONE
    XCUIElement *getTheAppButton = safari.staticTexts[@"GET THE APP"];
    [self waitForElement:getTheAppButton];
#else
    XCUIElement *safariWindow = safari.windows.firstMatch;
    [self waitForElement:safariWindow];
#endif
    
    [self.testApp activate];
}

- (void)testSilentAADLogin_withNoTokensInCache
{
    MSIDAutomationTestRequest *silentRequest = [self.class.confProvider defaultAppRequest];
    silentRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:silentRequest];
    [self acquireTokenSilent:config];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
}

- (void)testSilentAADLogin_withNoUserProvided_multipleUsersInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    // User 1.
    MSIDAutomationTestRequest *firstRequest = [self.class.confProvider defaultAppRequest];
    firstRequest.uiBehavior = @"always";
    firstRequest.loginHint = self.primaryAccount.account;
    [self runSharedAADLoginWithTestRequest:firstRequest];
    
    // User 2
    MSIDAutomationTestRequest *secondRequest = [self.class.confProvider defaultAppRequest];
    secondRequest.uiBehavior = @"always";
    secondRequest.loginHint = self.testConfiguration.accounts[1].account;
    [self runSharedAADLoginWithTestRequest:secondRequest];

    // User 1, silent login.
    firstRequest.loginHint = nil;
    NSDictionary *config = [self configWithTestRequest:firstRequest];
    [self acquireTokenSilent:config];
    [self assertErrorCode:@"AD_ERROR_CACHE_MULTIPLE_USERS"];
}

- (void)testAcquireTokenByRefreshToken_withAADRefreshToken
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"always";
    request.loginHint = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterPassword];
    
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    NSString *refreshToken = result.refreshToken;
    XCTAssertNotNil(refreshToken);
    [self closeResultView];
    
    [self clearKeychain];
    
    MSIDAutomationTestRequest *refreshTokenRequest = [self.class.confProvider defaultAppRequest];
    refreshTokenRequest.refreshToken = refreshToken;

    NSDictionary *refreshTokenConfig = [self configWithTestRequest:refreshTokenRequest];

    [self acquireTokenWithRefreshToken:refreshTokenConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    refreshTokenRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self runSharedSilentAADLoginWithTestRequest:refreshTokenRequest];
}

#pragma mark - Private

- (void)signInWithAnotherAccount
{
    XCUIElement *signIn = self.testApp.links[@"Sign in with another account"];
    [self waitForElement:signIn];
    [signIn msidTap];
}

@end
