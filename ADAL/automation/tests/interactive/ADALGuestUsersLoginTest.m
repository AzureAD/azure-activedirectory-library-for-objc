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
#import "ADALBaseUITest.h"
#import "XCTestCase+TextFieldTap.h"
#import "XCUIElement+CrossPlat.h"

@interface ADALGuestUsersLoginTest : ADALBaseUITest

@end

@implementation ADALGuestUsersLoginTest

- (void)setUp
{
    [super setUp];

    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureGuestUser];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

// #347620
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView_andGuestUserInGuestTenantOnly
{
    MSIDAutomationTestRequest *guestRequest = [self.class.confProvider defaultAppRequest];
    guestRequest.promptBehavior = @"always";
    guestRequest.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    
    NSDictionary *guestConfig = [self configWithTestRequest:guestRequest];
    [self acquireToken:guestConfig];
    [self aadEnterEmail];
    [self guestEnterUsername];
    [self guestEnterPassword];

    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Now do silent #296725
    guestRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentGuestConfig = [self configWithTestRequest:guestRequest];
    [self acquireTokenSilent:silentGuestConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:silentGuestConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:silentGuestConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Now do silent #296725 without providing user ID
    guestRequest.legacyAccountIdentifier = nil;
    NSDictionary *noIdSilentGuestConfig = [self configWithTestRequest:guestRequest];
    [self acquireTokenSilent:noIdSilentGuestConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];
}

// Test #347622
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView_andGuestUserInHomeAndGuestTenant
{
    // Sign in home tenant
    MSIDAutomationTestRequest *homeRequest = [self.class.confProvider defaultAppRequest];
    homeRequest.promptBehavior = @"always";
    homeRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    
    NSDictionary *homeConfig = [self configWithTestRequest:homeRequest];
    [self acquireToken:homeConfig];
    [self aadEnterEmail];
    [self guestEnterUsername];
    [self guestEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);

    [self closeResultView];

    // Sign in into guest tenant
    MSIDAutomationTestRequest *guestRequest = [self.class.confProvider defaultAppRequest];
    guestRequest.promptBehavior = @"always";
    guestRequest.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    
    NSDictionary *guestConfig = [self configWithTestRequest:guestRequest];
    [self acquireToken:guestConfig];
    [self aadEnterEmail];
    [self guestEnterUsername];
    [self guestEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);

    [self closeResultView];

    // Do silent for home tenant
    homeRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentHomeConfig = [self configWithTestRequest:homeRequest];
    [self expireAccessToken:silentHomeConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentHomeConfig];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);
    [self closeResultView];

    // Do silent for guest tenant
    guestRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentGuestConfig = [self configWithTestRequest:guestRequest];
    [self expireAccessToken:silentGuestConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentGuestConfig];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
}

- (void)testInteractiveAndSilentAADLogin_withPromptAuto_noLoginHint_ADALWebView_andGuestUserInHomeAndGuestTenant
{
    // Sign in home tenant
    MSIDAutomationTestRequest *homeRequest = [self.class.confProvider defaultAppRequest];
    homeRequest.promptBehavior = @"always";
    homeRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    
    NSDictionary *homeConfig = [self configWithTestRequest:homeRequest];
    [self acquireToken:homeConfig];
    [self aadEnterEmail];
    [self guestEnterUsername];
    [self guestEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);

    [self closeResultView];
    [self clearCookies];

    // Sign in into guest tenant with prompt auto. Should sign in silently
    MSIDAutomationTestRequest *guestRequest = [self.class.confProvider defaultAppRequest];
    guestRequest.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    guestRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *guestConfig = [self configWithTestRequest:guestRequest];
    [self acquireToken:guestConfig];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];
}

- (void)guestEnterUsername
{
    XCUIElement *usernameTextField = [self.testApp.textFields firstMatch];
    [self waitForElement:usernameTextField];
    [self tapElementAndWaitForKeyboardToAppear:usernameTextField];
    [usernameTextField activateTextField];
    [usernameTextField typeText:self.primaryAccount.username];
}

- (void)guestEnterPassword
{
    XCUIElement *passwordTextField = [self.testApp.secureTextFields firstMatch];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField activateTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
