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

@interface ADALLegacyiOSBrokerTests : ADALBaseiOSUITest

@end

@implementation ADALLegacyiOSBrokerTests

static BOOL brokerAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead
    if (!brokerAppInstalled)
    {
        brokerAppInstalled = YES;
        [self removeAppWithId:@"legacy_broker"];
        [self.testApp activate];
        [self installAppWithId:@"legacy_broker"];
        [self allowNotificationsInSystemAlert];
        [self.testApp activate];
        [self closeResultView];
    }

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureGuestUser];
    [self loadTestConfiguration:configurationRequest];
}

// TODO: older Authenticator build is not available anymore, re-enable this test if it's still necessary with a resigned authenticator build
- (void)DISABLED_testBrokerLoginWithGuestUsers_whenInGuestTenant_andDeviceRegistered_andLegacyBroker
{
    [self registerDeviceInAuthenticator];
    XCUIApplication *brokerApp = [self brokerApp];

    // We expect auth UI to appear
    XCUIElement *webView = [brokerApp.webViews elementBoundByIndex:0];
    XCTAssertTrue([webView waitForExistenceWithTimeout:10]);
    
    [self aadEnterEmail:self.primaryAccount.account app:brokerApp];
    [self enterPassword:self.primaryAccount.password app:brokerApp];

    __auto_type cancelAuthButton = brokerApp.buttons[@"Cancel"];
    __auto_type registerButton = brokerApp.tables.buttons[@"Register device"];
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"exists = 0"];
    [self expectationForPredicate:predicate evaluatedWithObject:cancelAuthButton handler:nil];
    [self expectationForPredicate:predicate evaluatedWithObject:registerButton handler:nil];
    [self waitForExpectationsWithTimeout:60.0f handler:nil];

    [self.testApp activate];
    
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.uiBehavior = @"auto";
    request.brokerEnabled = YES;
    request.loginHint = self.primaryAccount.account;
    request.configurationAuthority = [NSString stringWithFormat:@"https://%@/%@", self.testConfiguration.authorityHost, self.primaryAccount.targetTenantId];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self brokerApp];
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

@end
