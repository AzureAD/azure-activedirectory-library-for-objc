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

@interface ADALCacheRemovalTests : ADALBaseUITest

@end

@implementation ADALCacheRemovalTests

- (void)testRemoveAllForUserIdAndClientId_whenMultipleUsersAndClientsInCache
{
    /*
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
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
               @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive"
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireTokenSilent:config2];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    self.primaryAccount = self.testConfiguration.accounts[1];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES,
               @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
               @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
               };

    config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    */

}

- (void)testRemoveAllForClientId_whenMultipleUsersAndClientsInCache
{

}

- (void)testWipeAllForUserId_whenMultipleUsersAndClientsInCache
{

}

@end
