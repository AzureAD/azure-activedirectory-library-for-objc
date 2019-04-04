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

    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    [self loadTestConfiguration:configurationRequest];
}

- (void)testAuthorityMigration_withPublicCloud_whenAppUpdatingAuthorities
{
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"ww-alias" tenantId:nil];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    [self clearCookies];
    
    MSIDAutomationTestRequest *aliasRequest = [self.class.confProvider defaultAppRequest];
    aliasRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"ww" tenantId:nil];
    
    NSDictionary *aliasConfig = [self configWithTestRequest:aliasRequest];

    // Acquire token again.
    [self acquireToken:aliasConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Expire access token
    request.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentConfig = [self configWithTestRequest:request];
    [self expireAccessToken:silentConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now refresh token
    aliasRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentAliasConfig = [self configWithTestRequest:aliasRequest];
    [self acquireTokenSilent:silentAliasConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testAuthorityMigration_withPublicCloud_andFRT_whenAppsUsingDifferentAuthorities
{
    MSIDAutomationTestRequest *firstRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstRequest.promptBehavior = @"always";
    firstRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"ww" tenantId:nil];
    
    NSDictionary *firstConfig = [self configWithTestRequest:firstRequest];
    [self acquireToken:firstConfig];

    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    MSIDAutomationTestRequest *secondRequest = [self.class.confProvider defaultFociRequestWithBroker];
    secondRequest.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"ww-alias" tenantId:nil];
    
    NSDictionary *secondConfig = [self configWithTestRequest:secondRequest];
    [self acquireTokenSilent:secondConfig];
    [self assertAccessTokenNotNil];
}

@end
