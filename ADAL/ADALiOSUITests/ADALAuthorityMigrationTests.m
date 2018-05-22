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

@interface ADALAuthorityMigrationTests : ADALBaseUITest

@end

@implementation ADALAuthorityMigrationTests

- (void)setUp
{
    [super setUp];
    [self clearCache];
    [self clearCookies];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testAuthorityMigration_withPublicCloud_whenAppUpdatingAuthorities
{
    NSDictionary *config = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @NO,
                             @"authority": @"https://login.windows.net/common"
                             };

    config = [self.testConfiguration configWithAdditionalConfiguration:config];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    [self clearCookies];

    config = @{@"authority": @"https://login.microsoftonline.com/common",
               @"prompt": @"auto"};

    config = [self.testConfiguration configWithAdditionalConfiguration:config];

    // Acquire token again.
    [self acquireToken:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    config = @{@"authority": @"https://login.windows.net/common",
               @"user_identifier" : self.primaryAccount.account};

    config = [self.testConfiguration configWithAdditionalConfiguration:config];
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    config = @{@"authority": @"https://login.microsoftonline.com/common",
               @"prompt": @"auto"};
    config = [self.testConfiguration configWithAdditionalConfiguration:config];

    // Now refresh token
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testAuthorityMigration_withPublicCloud_andFRT_whenAppsUsingDifferentAuthorities
{
    // TODO: add foci support to the lab API
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                             @"authority": @"https://login.microsoftonline.com/common"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES,
               @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707",
               @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive",
               @"authority": @"https://login.windows.net/common"
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireTokenSilent:config2];
    [self assertAccessTokenNotNil];
}

@end
