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

@interface ADALGuestUsersLoginTest : ADALBaseUITest

@end

@implementation ADALGuestUsersLoginTest

- (void)setUp
{
    [super setUp];
    [self clearCache];
    [self clearCookies];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureGuestUser];
    [self loadTestConfiguration:configurationRequest];
}

// #347620
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView_andGuestUserInGuestTenantOnly
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params account:self.primaryAccount];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];

    // Now do silent #296725
    NSDictionary *silentParams = @{
                                   @"user_identifier" : self.primaryAccount.account
                                   };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams account:self.primaryAccount];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
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

    // Now do silent #296725 without providing user ID
    silentParams = @{};

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams account:self.primaryAccount];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
    [self closeResultView];
}

// Test #347622
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView_andGuestUserInHomeAndGuestTenant
{
    // Sign in home tenant
    NSDictionary *homeParams = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"authority": @"https://login.microsoftonline.com/common",
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                             };

    homeParams = [self.testConfiguration configWithAdditionalConfiguration:homeParams account:self.primaryAccount];

    [self acquireToken:homeParams];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);

    [self closeResultView];

    // Sign in into guest tenant
    NSDictionary *guestParams = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                             };

    guestParams = [self.testConfiguration configWithAdditionalConfiguration:guestParams account:self.primaryAccount];
    [self acquireToken:guestParams];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);

    [self closeResultView];

    // Do silent for home tenant
    NSDictionary *silentHomeParams = @{@"user_identifier": self.primaryAccount.account,
                                       @"authority": @"https://login.microsoftonline.com/common",
                                       @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                                       @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
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
                                        @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                                        @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                                        };
    silentGuestParams = [self.testConfiguration configWithAdditionalConfiguration:silentGuestParams account:self.primaryAccount];
    [self expireAccessToken:silentGuestParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentGuestParams];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);
}

- (void)testInteractiveAndSilentAADLogin_withPromptAuto_noLoginHint_ADALWebView_andGuestUserInHomeAndGuestTenant
{
    // Sign in home tenant
    NSDictionary *homeParams = @{
                                 @"prompt_behavior" : @"always",
                                 @"validate_authority" : @YES,
                                 @"authority": @"https://login.microsoftonline.com/common",
                                 @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                                 @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                                 };

    homeParams = [self.testConfiguration configWithAdditionalConfiguration:homeParams account:self.primaryAccount];

    [self acquireToken:homeParams];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.homeTenantId);

    [self closeResultView];
    [self clearCookies];

    // Sign in into guest tenant
    NSDictionary *guestParams = @{
                                  @"user_identifier": self.primaryAccount.account,
                                  @"prompt_behavior" : @"auto",
                                  @"validate_authority" : @YES,
                                  @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c", // TODO: the lab needs to add a multi-tenant app, otherwise this test cannot work
                                  @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                                  };

    guestParams = [self.testConfiguration configWithAdditionalConfiguration:guestParams account:self.primaryAccount];
    [self acquireToken:guestParams];
    [self assertAccessTokenNotNil];

    XCTAssertEqualObjects([self resultIDTokenClaims][@"tid"], self.primaryAccount.targetTenantId);

    [self closeResultView];
}

@end
