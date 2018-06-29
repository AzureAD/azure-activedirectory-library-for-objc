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

@interface ADALiOSOlderADALCoexistenceCacheTests : ADALBaseUITest

@end

@implementation ADALiOSOlderADALCoexistenceCacheTests

static BOOL olderADALAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead
    if (!olderADALAppInstalled)
    {
        olderADALAppInstalled = YES;
        [self installAppWithId:@"adal_1_2_x"];
        [self.testApp activate];
        [self closeResultView];
    }

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

// #296892
- (void)testCoexistenceWithADAL1_2_startSigninInADAL1_2_andDoTokenRefresh
{
    // Install and sign into older ADAL
    XCUIApplication *olderApp = [self olderADALApp];
    [self selectCorrectProfile:olderApp];

    __auto_type userNameField = [[olderApp textFields] elementBoundByIndex:0];
    [self waitForElement:userNameField];
    [self tapElementAndWaitForKeyboardToAppear:userNameField app:olderApp];
    [userNameField typeText:self.primaryAccount.username];
    [olderApp.buttons[@"prompt always"] tap];

    [self aadEnterPasswordInApp:olderApp];
    [self validateSuccessfulResultInApp:olderApp];

    [self.testApp activate];
    [olderApp terminate];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"resource": @"https://graph.windows.net",
                             @"authority": @"https://login.microsoftonline.com/common",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    [self acquireTokenSilent:config];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Before going to older app, expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    olderApp = [self olderADALApp];
    [olderApp.tabBars.buttons[@"Cache"] tap];
    [olderApp.tabBars.buttons[@"Acquire"] tap];
    userNameField = [[olderApp textFields] elementBoundByIndex:0];
    [self waitForElement:userNameField];
    [self tapElementAndWaitForKeyboardToAppear:userNameField app:olderApp];
    [userNameField typeText:self.primaryAccount.username];

    [olderApp.buttons[@"silent"] tap];
    [self validateSuccessfulResultInApp:olderApp];
    [olderApp terminate];
}

- (void)testCoexistenceWithADAL1_2_startSigninInNewADAL_andDoTokenRefresh
{
    [self.testApp activate];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"resource": @"https://graph.windows.net",
                             @"authority": @"https://login.microsoftonline.com/common",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    XCUIApplication *olderApp = [self olderADALApp];
    [self selectCorrectProfile:olderApp];
    [olderApp.buttons[@"silent"] tap];
    [self validateSuccessfulResultInApp:olderApp];
}

- (void)selectCorrectProfile:(XCUIApplication *)app
{
    // Because there's no automation app for 1.2.x ADAL, we just use the test app
    [app.tabBars.buttons[@"Settings"] tap];

    if ([app.buttons[@"Test App"] exists])
    {
        [app.buttons[@"Test App"] tap];
        [app.tables.staticTexts[@"OneDrive"] tap];
    }

    [app.tabBars.buttons[@"Acquire"] tap];
}

- (void)validateSuccessfulResultInApp:(XCUIApplication *)app
{
    __auto_type resultTextView = [app.textViews elementBoundByIndex:0];
    [self waitForElement:resultTextView];

    // Validate result returned
    XCTAssertTrue([resultTextView.value containsString:@"AD_SUCCEEDED"]);
    XCTAssertTrue([resultTextView.value containsString:@"ADTokenCacheStoreItem"]);
}

- (XCUIApplication *)olderADALApp
{
    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:@"adal_1_2_x"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *olderApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [olderApp activate];
    BOOL result = [olderApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);
    return olderApp;
}

@end
