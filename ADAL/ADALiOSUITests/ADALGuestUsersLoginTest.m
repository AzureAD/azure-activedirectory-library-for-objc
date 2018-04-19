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

    MSIDTestConfigurationRequest *configurationRequest = [MSIDTestConfigurationRequest new];
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

    NSDictionary *config = [self.testConfiguration configParametersWithAdditionalParams:params account:self.primaryAccount];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do silent #296725
    NSDictionary *silentParams = @{
                                   @"user_id" : self.primaryAccount.account
                                   };

    config = [self.testConfiguration configParametersWithAdditionalParams:silentParams account:self.primaryAccount];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do silent #296725 without providing user ID
    silentParams = @{};

    config = [self.testConfiguration configParametersWithAdditionalParams:silentParams account:self.primaryAccount];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

// Test #347622
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView_andGuestUserInHomeAndGuestTenant
{
    // Sign in home tenant
    NSDictionary *homeParams = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"authority": @"https://login.microsoftonline.com/common"
                             };

    homeParams = [self.testConfiguration configParametersWithAdditionalParams:homeParams account:self.primaryAccount];

    [self acquireToken:homeParams];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Sign in into guest tenant
    NSDictionary *guestParams = @{
                             @"prompt_behavior" : @"auto", // Since ADAL doesn't have cross tenant support, it's expected to prompt
                             @"validate_authority" : @YES
                             };

    guestParams = [self.testConfiguration configParametersWithAdditionalParams:guestParams account:self.primaryAccount];
    [self acquireToken:guestParams];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Do silent for home tenant
    NSDictionary *silentHomeParams = @{@"user_id": self.primaryAccount.account,
                                       @"authority": @"https://login.microsoftonline.com/common"
                                       };
    silentHomeParams = [self.testConfiguration configParametersWithAdditionalParams:silentHomeParams account:self.primaryAccount];
    [self expireAccessToken:silentHomeParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentHomeParams];

    // Do silent for guest tenant
    NSDictionary *silentGuestParams = @{@"user_id": self.primaryAccount.account};
    silentGuestParams = [self.testConfiguration configParametersWithAdditionalParams:silentGuestParams account:self.primaryAccount];
    [self expireAccessToken:silentGuestParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    [self acquireTokenSilent:silentGuestParams];
}

@end
