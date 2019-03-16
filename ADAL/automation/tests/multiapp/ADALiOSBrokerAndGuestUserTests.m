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
#import "XCUIElement+CrossPlat.h"

@interface ADALiOSBrokerAndGuestUserTests : ADALBaseiOSUITest

@end

@implementation ADALiOSBrokerAndGuestUserTests

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

    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureGuestUser];
    [self loadTestConfiguration:configurationRequest];
}

- (void)testBasicBrokerLoginWithGuestUsers
{
    MSIDAutomationTestRequest *adalRequest = [self.class.confProvider defaultAppRequest];
    adalRequest.promptBehavior = @"auto";
    adalRequest.loginHint = self.primaryAccount.account;
    adalRequest.legacyAccountIdentifier = self.primaryAccount.account;
    adalRequest.legacyAccountIdentifierType = @"optional_displayable";
    adalRequest.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    adalRequest.brokerEnabled = YES;
    
    NSDictionary *adalConfig = [self configWithTestRequest:adalRequest];
    [self acquireToken:adalConfig];

    XCUIApplication *brokerApp = [self brokerApp];
    [self aadEnterEmail:self.primaryAccount.account app:brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];

    [self waitForRedirectToTheTestApp];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:adalConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:adalConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];
}

- (void)testBrokerLoginWithGuestUsers_whenInHomeAndGuestTenants
{
    // Sign in home tenant
    MSIDAutomationTestRequest *homeRequest = [self.class.confProvider defaultAppRequest];
    homeRequest.promptBehavior = @"force";
    homeRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:nil];
    homeRequest.brokerEnabled = YES;
    homeRequest.loginHint = self.primaryAccount.account;
    homeRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *homeConfig = [self configWithTestRequest:homeRequest];
    [self acquireToken:homeConfig];

    // Expect sign in to be handled in broker
    XCUIApplication *brokerApp = [self brokerApp];
    [self aadEnterEmail:self.primaryAccount.account app:brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];

    [self waitForRedirectToTheTestApp];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);
    [self closeResultView];

    // Sign in into guest tenant
    MSIDAutomationTestRequest *guestRequest = [self.class.confProvider defaultAppRequest];
    guestRequest.brokerEnabled = YES;
    guestRequest.loginHint = self.primaryAccount.account;
    guestRequest.legacyAccountIdentifier = self.primaryAccount.account;
    guestRequest.promptBehavior = @"force";
    guestRequest.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    
    NSDictionary *guestConfig = [self configWithTestRequest:guestRequest];
    [self acquireToken:guestConfig];
    [self aadEnterEmail:self.primaryAccount.account app:brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];

    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Do silent for home tenant
    [self expireAccessToken:homeConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:homeConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);
    [self closeResultView];

    // Do silent for guest tenant
    [self expireAccessToken:guestConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:guestConfig];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
}

- (void)testBrokerLoginWithGuestUsers_whenGuestTenant_andDeviceRegistered
{
    [self registerDeviceInAuthenticatorAndCompleteAuth:YES];
    [self.testApp launch];
    [self.testApp activate];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"auto";
    request.loginHint = self.primaryAccount.account;
    request.legacyAccountIdentifier = self.primaryAccount.account;
    request.legacyAccountIdentifierType = @"optional_displayable";
    request.brokerEnabled = YES;
    request.configurationAuthority = [self.testConfiguration authorityWithTenantId:self.primaryAccount.targetTenantId];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self waitForRedirectToTheTestApp];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    [self unregisterDeviceInAuthenticator];
}

@end
