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

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureGuestUser];
    [self loadTestConfiguration:configurationRequest];
}

- (void)testBasicBrokerLoginWithGuestUsers
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params account:self.primaryAccount];
    [self acquireToken:config];

    XCUIApplication *brokerApp = [self brokerApp];

    [self guestEnterUsernameInApp:brokerApp];
    [self guestEnterPasswordInApp:brokerApp];

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
}

- (void)testBrokerLoginWithGuestUsers_whenInHomeAndGuestTenants
{
    // Sign in home tenant
    NSDictionary *homeParams = @{
                                 @"prompt_behavior" : @"force",
                                 @"validate_authority" : @YES,
                                 @"authority": @"https://login.microsoftonline.com/common",
                                 @"use_broker": @YES,
                                 @"user_identifier" : self.primaryAccount.account
                                 };

    homeParams = [self.testConfiguration configWithAdditionalConfiguration:homeParams account:self.primaryAccount];

    [self acquireToken:homeParams];

    // Expect sign in to be handled in broker
    XCUIApplication *brokerApp = [self brokerApp];

    [self guestEnterUsernameInApp:brokerApp];
    [self guestEnterPasswordInApp:brokerApp];

    [self waitForRedirectToTheTestApp];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);
    [self closeResultView];

    // Sign in into guest tenant
    NSDictionary *guestParams = @{
                                  @"prompt_behavior" : @"force",
                                  @"validate_authority" : @YES,
                                  @"use_broker": @YES,
                                  @"user_identifier" : self.primaryAccount.account
                                  };

    guestParams = [self.testConfiguration configWithAdditionalConfiguration:guestParams account:self.primaryAccount];
    [self acquireToken:guestParams];
    [self guestEnterUsernameInApp:brokerApp];
    [self guestEnterPasswordInApp:brokerApp];

    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Do silent for home tenant
    NSDictionary *silentHomeParams = @{@"user_identifier": self.primaryAccount.account,
                                       @"authority": @"https://login.microsoftonline.com/common",
                                       };
    silentHomeParams = [self.testConfiguration configWithAdditionalConfiguration:silentHomeParams account:self.primaryAccount];
    [self expireAccessToken:silentHomeParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentHomeParams];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);

    [self closeResultView];

    // Do silent for guest tenant
    NSDictionary *silentGuestParams = @{@"user_identifier": self.primaryAccount.account,
                                        };
    silentGuestParams = [self.testConfiguration configWithAdditionalConfiguration:silentGuestParams account:self.primaryAccount];
    [self expireAccessToken:silentGuestParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentGuestParams];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
}

- (void)testBrokerLoginWithGuestUsers_whenGuestTenant_andDeviceRegistered
{
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];

    // We expect auth UI to appear
    XCUIElement *webView = [brokerApp.webViews elementBoundByIndex:0];
    XCTAssertTrue([webView waitForExistenceWithTimeout:10]);

    [self guestEnterUsernameInApp:brokerApp];
    [self guestEnterPasswordInApp:brokerApp];
    __auto_type unregisterButton = brokerApp.tables.buttons[@"Unregister device"];
    [self waitForElement:unregisterButton];
    [self.testApp activate];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params account:self.primaryAccount];
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
