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
#import "NSDictionary+ADALiOSUITests.h"
#import "XCUIElement+CrossPlat.h"

@interface ADALCacheRemovalTests : ADALBaseUITest

@end

@implementation ADALCacheRemovalTests

/* TODO: these tests need to be converted into integration tests */

- (void)testRemoveAllForUserIdAndClientId_whenMultipleUsersAndClientsInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

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

    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config2];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Delete specific tokens
    NSDictionary *removeConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                                   @"client_id": self.testConfiguration.clientId};

    [self deleteTokens:removeConfig];

    NSDictionary *silentConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                                   @"client_id": self.testConfiguration.clientId
                                   };

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertError:@"AD_ERROR_USER_INPUT_NEEDED"];
    [self closeResultView];

    silentConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                     @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c"
                     };

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testRemoveAllForClientId_whenMultipleUsersAndClientsInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

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

    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config2];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Delete specific tokens
    NSDictionary *removeConfig = @{@"client_id": self.testConfiguration.clientId};

    [self deleteTokens:removeConfig];

    NSDictionary *silentConfig = @{@"client_id": self.testConfiguration.clientId};

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertError:@"AD_ERROR_USER_INPUT_NEEDED"];
    [self closeResultView];

    silentConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                     @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c"
                     };

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testWipeAllForUserId_whenMultipleUsersAndClientsInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

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

    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params = @{
               @"prompt_behavior" : @"always",
               @"validate_authority" : @YES
               };

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config2];
    [self aadEnterEmail];
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Delete specific tokens
    NSDictionary *removeConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username]};
    [self deleteTokens:removeConfig];

    NSDictionary *silentConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                                   @"client_id": self.testConfiguration.clientId
                                   };

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertError:@"AD_ERROR_USER_INPUT_NEEDED"];
    [self closeResultView];

    silentConfig = @{@"user_identifier": [self.testConfiguration.accounts[0] username],
                     @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c"
                     };
    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertError:@"AD_ERROR_USER_INPUT_NEEDED"];
    [self closeResultView];

    silentConfig = @{@"user_identifier": self.primaryAccount.username,
                     @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c"
                     };

    [self acquireTokenSilent:[self.testConfiguration configWithAdditionalConfiguration:silentConfig]];
    [self assertAccessTokenNotNil];

}

- (void)deleteTokens:(NSDictionary *)config
{
    [self.testApp.buttons[@"Delete specific tokens"] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidPasteText:[config toJsonString] application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
    [self closeResultView];
}

@end
