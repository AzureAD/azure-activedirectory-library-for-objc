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

@interface ADALiOSNoBrokerTests : ADALBaseUITest

@property (nonatomic) id interruptionMonitor;

@end

@implementation ADALiOSNoBrokerTests

- (void)setUp
{
    [super setUp];

    _interruptionMonitor = [self addUIInterruptionMonitorWithDescription:@"Notifications permission" handler:^BOOL(XCUIElement *alert) {

        [alert.buttons[@"Allow"] tap];
        return YES;
    }];

    [self removeAppWithId:@"broker"];

    [self.testApp activate];
}

- (void)tearDown
{
    [super tearDown];
    [self removeUIInterruptionMonitor:_interruptionMonitor];
}

- (void)testFirstTimeAuthenticatorInstallPrompt
{
    [self clearKeychain];
    [self openAppInstallURLForAppId:@"broker"];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMAMEnabled];
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterPassword];

    __auto_type registerButton = self.testApp.buttons[@"Get the app"];
    [self waitForElement:registerButton];
    [registerButton tap];

    XCUIApplication *appStore = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.MobileStore"];
    BOOL result = [appStore waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    __auto_type appTitle = appStore.otherElements[@"Microsoft Authenticator "];
    [self waitForElement:appTitle];

    XCUIApplication *brokerApp = [self installAppWithIdWithSafariOpen:@"broker"];
    [self aadEnterPasswordInApp:brokerApp];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];

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
