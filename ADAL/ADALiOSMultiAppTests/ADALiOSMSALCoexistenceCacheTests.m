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

@interface ADALiOSMSALCoexistenceCacheTests : ADALBaseUITest

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
                             @"validate_authority" : @YES
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
               @"scopes": @[[self.testConfiguration.resource stringByAppendingString:@"/.default"]]
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

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirstAndUseScopes_andSameClientId
{
    self.testApp = [self msalTestApp];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"scopes": @[@"user.read", @"user.write"]
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

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

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    // Acquire token silent
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
                             @"scopes": @[[self.testConfiguration.resource stringByAppendingString:@"/.default"]]
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

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

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    // Acquire token silent
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andDifferentClient_withFociSupport
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andDifferentClient_withFociSupport
{
    self.testApp = [self msalTestApp];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive",
                             @"scopes": @[@"user.read"]
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
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireTokenSilent:config2];
    [self assertAccessTokenNotNil];

    // Go back to MSAL test app
    self.testApp = [self msalTestApp];

    // Acquire token silent
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andSameClientId_andNoUserIdentifierProvided
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andDifferentClient_withFociSupport_andAuthorityMigration
{

}

// Step up test
// test when only one type of cache there

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
