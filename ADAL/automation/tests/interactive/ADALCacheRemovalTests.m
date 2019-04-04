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
#import "MSIDAutomationActionConstants.h"

@interface ADALCacheRemovalTests : ADALBaseUITest

@end

@implementation ADALCacheRemovalTests

- (void)setUp
{
    [super setUp];
    
    MSIDAutomationConfigurationRequest *configurationRequest = [MSIDAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    [self loadTestConfiguration:configurationRequest];
    
    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);
}

/* TODO: these tests need to be converted into integration tests */

- (void)testRemoveAllForUserIdAndClientId_whenMultipleClientTokensInCache_shouldDeleteOnlyClientTokens
{
    [self runSharedMultiAppSignin];

    // Delete specific tokens
    MSIDAutomationTestRequest *firstLabAppRequest = [self.class.confProvider defaultAppRequest];
    firstLabAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self deleteTokens:[self configWithTestRequest:firstLabAppRequest]];
    [self closeResultView];

    [self acquireTokenSilent:[self configWithTestRequest:firstLabAppRequest]];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];

    MSIDAutomationTestRequest *firstFociAppRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstFociAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self acquireTokenSilent:[self configWithTestRequest:firstFociAppRequest]];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testRemoveAllForClientId_whenMultipleUsersAndClientsInCache
{
    [self runSharedMultiUserSignin];
    
    // Delete specific tokens
    MSIDAutomationTestRequest *deleteClientIdRequest = [MSIDAutomationTestRequest new];
    deleteClientIdRequest.clientId = self.testConfiguration.clientId;
    [self deleteTokens:deleteClientIdRequest.jsonDictionary];
    [self closeResultView];

    // Silent for account 1, app 1
    MSIDAutomationTestRequest *firstLabAppRequest = [self.class.confProvider defaultAppRequest];
    firstLabAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self acquireTokenSilent:[self configWithTestRequest:firstLabAppRequest]];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];
    
    // Silent for account 2, app 1
    MSIDAutomationTestRequest *secondLabAppRequest = [self.class.confProvider defaultAppRequest];
    secondLabAppRequest.legacyAccountIdentifier = [self.testConfiguration.accounts[1] account];
    [self acquireTokenSilent:[self configWithTestRequest:secondLabAppRequest]];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];
    
    // Silent for account 1, app 2, should succeed
    MSIDAutomationTestRequest *firstFociAppRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstFociAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self acquireTokenSilent:[self configWithTestRequest:firstFociAppRequest]];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testWipeAllForUserId_whenMultipleUsersAndClientsInCache
{
    [self runSharedMultiUserSignin];

    // Delete specific tokens
    MSIDAutomationTestRequest *deleteRequest = [MSIDAutomationTestRequest new];
    deleteRequest.legacyAccountIdentifier = [self.testConfiguration.accounts[0] username];
    [self deleteTokens:deleteRequest.jsonDictionary];
    [self closeResultView];
    
    // Silent for account 1, app 1
    MSIDAutomationTestRequest *firstLabAppRequest = [self.class.confProvider defaultAppRequest];
    firstLabAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self acquireTokenSilent:[self configWithTestRequest:firstLabAppRequest]];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];
    
    // Silent for account 2, app 1
    MSIDAutomationTestRequest *secondLabAppRequest = [self.class.confProvider defaultAppRequest];
    secondLabAppRequest.legacyAccountIdentifier = [self.testConfiguration.accounts[1] account];
    [self acquireTokenSilent:[self configWithTestRequest:secondLabAppRequest]];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Silent for account 1, app 2, should fail
    MSIDAutomationTestRequest *firstFociAppRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstFociAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self acquireTokenSilent:[self configWithTestRequest:firstFociAppRequest]];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];
}

- (void)runSharedMultiAppSignin
{
    // Sign account 1 into app 1
    MSIDAutomationTestRequest *firstLabAppRequest = [self.class.confProvider defaultAppRequest];
    firstLabAppRequest.promptBehavior = @"always";
    firstLabAppRequest.loginHint = self.primaryAccount.account;
    firstLabAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self runSharedAADLoginWithTestRequest:firstLabAppRequest];
    
    // Sign account 1 into app 2
    MSIDAutomationTestRequest *firstFociAppRequest = [self.class.confProvider defaultFociRequestWithoutBroker];
    firstFociAppRequest.promptBehavior = @"always";
    firstFociAppRequest.loginHint = self.primaryAccount.account;
    firstFociAppRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self runSharedAADLoginWithTestRequest:firstFociAppRequest];
}

- (void)runSharedMultiUserSignin
{
    [self runSharedMultiAppSignin];
    
    // Sign account 2 into app 1
    [self loadPasswordForAccount:self.primaryAccount];
    MSIDAutomationTestRequest *secondLabAppRequest = [self.class.confProvider defaultAppRequest];
    secondLabAppRequest.promptBehavior = @"always";
    secondLabAppRequest.loginHint = [self.testConfiguration.accounts[1] account];
    secondLabAppRequest.legacyAccountIdentifier = [self.testConfiguration.accounts[1] account];
    [self runSharedAADLoginWithTestRequest:secondLabAppRequest];
}

- (void)deleteTokens:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_REMOVE_ACCOUNT_ACTION_IDENTIFIER withConfig:config];
}

@end
