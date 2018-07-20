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

//static BOOL msalAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead

    if (!msalAppInstalled)
    {
        msalAppInstalled = YES;
        [self installAppWithId:@"msal_objc"];
        [self.testApp activate];
        [self closeResultView];
    }

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andSameClientId
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive",
                             @"resource": @"https://graph.microsoft.com"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    self.testApp = [self msalTestApp];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES,
               @"scopes": @"https://graph.microsoft.com/.default",
               @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
               @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive", // TODO: replace this with lab test app, when redirect uris are added in lab
               @"user_identifier": self.primaryAccount.homeAccountId,
               // MSAL doesn't have authority migration feature yet, so we need to use login.windows.net authority
               @"authority": [NSString stringWithFormat:@"https://login.windows.net/%@", self.primaryAccount.targetTenantId]
               };

    config = [self.testConfiguration configWithAdditionalConfiguration:params];

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

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirstAndUseDefaultScope_andSameClientId
{
    self.testApp = [self msalTestApp];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"scopes": @"https://graph.microsoft.com/.default",
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive",
                             @"resource": @"https://graph.microsoft.com",
                             @"authority": @"https://login.microsoftonline.com/organizations",
                             @"ui_behavior": @"force",
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    self.testApp = [XCUIApplication new];
    [self.testApp activate];

    NSMutableDictionary *mutableParams = [config mutableCopy];
    mutableParams[@"authority"] = @"https://login.microsoftonline.com/common";

    // Acquire token silent
    [self acquireTokenSilent:mutableParams];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    [self expireAccessToken:mutableParams];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do token refresh
    [self acquireTokenSilent:mutableParams];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    mutableParams[@"user_identifier"] = self.primaryAccount.homeAccountId;

    // Acquire token silent
    [self acquireTokenSilent:mutableParams];
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

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive",
                             @"scopes": @"https://graph.microsoft.com/.default",
                             @"authority": @"https://login.microsoftonline.com/organizations",
                             @"ui_behavior": @"force",
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Switch back to the new ADAL app
    self.testApp = [XCUIApplication new];
    [self.testApp activate];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES,
               @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
               @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
               @"authority": @"https://login.windows.net/common"
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireTokenSilent:config2];
    [self assertAccessTokenNotNil];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    NSMutableDictionary *mutableConfig = [config mutableCopy];
    mutableConfig[@"user_identifier"] = self.primaryAccount.homeAccountId;

    // Acquire token silent
    [self acquireTokenSilent:mutableConfig];
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

    NSDictionary *params = @{
                             @"prompt_behavior" : @"auto",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"use_broker": @YES,
                             @"scopes": @"https://graph.microsoft.com/.default",
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];

    XCUIApplication *brokerApp = [self brokerApp];

    [self aadEnterPasswordInApp:brokerApp];
    [self waitForRedirectToTheTestApp];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    NSMutableDictionary *mutableConfig = [config mutableCopy];
    mutableConfig[@"user_identifier"] = nil;
    mutableConfig[@"user_legacy_identifier"] = self.primaryAccount.username;
    mutableConfig[@"authority"] = [NSString stringWithFormat:@"https://login.windows.net/%@", self.primaryAccount.targetTenantId];

    // Acquire token silent
    [self acquireTokenSilent:mutableConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (XCUIApplication *)msalTestApp
{
    NSDictionary *appConfiguration = [self.class.accountsProvider appInstallForConfiguration:@"msal_objc"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *msalApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [msalApp activate];
    BOOL result = [msalApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);
    return msalApp;
}

@end
