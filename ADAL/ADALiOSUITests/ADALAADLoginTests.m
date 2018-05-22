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
#import "NSDictionary+ADALiOSUITests.h"
#import "XCTestCase+TextFieldTap.h"

@interface ADALAADInteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALAADInteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    [self clearCache];
    [self clearCookies];
}

#pragma mark - Tests

// #290995 iteration 1
- (void)testInteractiveAndSilentAADLogin_withPromptAlways_noLoginHint_ADALWebView
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

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
    
    // Acquire token again.
    [self acquireToken:config];
    
    [self assertAuthUIAppear];
    [self closeAuthUI];
    [self closeResultView];

    // Now do silent #296725
    NSDictionary *silentParams = @{
                     @"user_identifier" : self.primaryAccount.account,
                     @"client_id" : self.testConfiguration.clientId,
                     @"authority" : self.testConfiguration.authority,
                     @"resource" : self.testConfiguration.resource
                     };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
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
    silentParams = @{
                     @"client_id" : self.testConfiguration.clientId,
                     @"authority" : self.testConfiguration.authority,
                     @"resource" : self.testConfiguration.resource
                     };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testInteractiveAADLogin_withPromptAlways_noLoginHint_ADALWebView_andAuthCanceled
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];
    [self aadEnterEmail];
    [self closeAuthUI];
    [self assertError:@"AD_ERROR_UI_USER_CANCEL"];
}

// #290995 iteration 2
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_ADALWebView
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    
    [self assertAuthUIAppear];
}

// #290995 iteration 3
- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_ADALWebView
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    
    // Wait for result immediately, no user action required.
    [self assertAccessTokenNotNil];
}

// #290995 iteration 4
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_PassedInWebView
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"web_view" : @"passed_in"
                             };
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    
    [self assertAuthUIAppear];
}

// #296277: FoCI: Acquire a token using an FRT
- (void)testAADLogin_withPromptAlways_noLoginHint_acquireTokenUsingFRT
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: add foci support to the lab API
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
}

// #296755: FoCI : MRRT Fallback when FRT Fails
- (void)testAADLogin_withPromptAlways_noLoginHint_MRRTFallbackWhenFRTFails
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: add foci support to the lab API
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
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    NSDictionary *keyParams = @{
                                @"user_identifier" : self.primaryAccount.account,
                                @"client_id" : @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                                @"authority" : self.testConfiguration.authority,
                                @"resource" : self.testConfiguration.resource
                                };
    
    [self expireAccessToken:keyParams];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    keyParams = @{
                  @"user_identifier" : self.primaryAccount.account,
                  @"client_id" : @"foci-1",
                  @"authority" : self.testConfiguration.authority
                  };
    
    [self invalidateRefreshToken:keyParams];
    [self assertRefreshTokenInvalidated];
    [self closeResultView];
    
    [self acquireTokenSilent:config];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// #296753: Login Multiple Accounts
- (void)testAADLogin_withPromptAlways_LoginHint_loginMultipleAccounts
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: remove this, once API is fixed to return multiple accounts
    //[self.testConfiguration addAdditionalAccount:self.accountsProvider.defaultLabAccount];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    // User 1.
    NSMutableDictionary *params = [@{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             } mutableCopy];
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    // User 2.
    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params[@"user_identifier"] = self.primaryAccount.account;
    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config2];
    
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];
    
    // User 1, silent login.
    self.primaryAccount = self.testConfiguration.accounts[0];
    params[@"user_identifier"] = self.primaryAccount.account;
    config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];

    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // User 2, silent login.
    [self acquireTokenSilent:config2];
    [self assertAccessTokenNotNil];
}

// #296758: Different ADUserIdentifierType settings
- (void)testAADLogin_withPromptAlways_LoginHint_differentUserTypeSettings
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.needsMultipleUsers = YES;
    [self loadTestConfiguration:configurationRequest];

    // TODO: remove this, once API is fixed to return multiple users
    //[self.testConfiguration addAdditionalAccount:self.accountsProvider.defaultAccount];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    MSIDTestAccount *firstAccount = self.testConfiguration.accounts[0];
    MSIDTestAccount *secondaryAccount = self.testConfiguration.accounts[1];

    // Optional Displayable, User 1.
    NSMutableDictionary *params = [@{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : secondaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             } mutableCopy];

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    // Change account to nr 2
    [self signInWithAnotherAccount];

    // Enter username and pwd for user 2
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", firstAccount.account]];
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", firstAccount.password]];

    // Should succeed
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];

    // Required Displayable, User 1.
    params[@"user_identifier_type"] = @"required_displayable";

    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config2];

    // Change account
    [self signInWithAnotherAccount];
    
    // Enter username and pwd for user 2
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", firstAccount.account]];
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", firstAccount.password]];

    // Should fail
    [self assertError:@"AD_ERROR_SERVER_WRONG_USER"];
    [self closeResultView];
    
    // RequiredDisplayableId and not changing the user

    params[@"user_identifier"] = firstAccount.account;
    NSDictionary *config3 = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config3];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// 296732: Company Portal Install Prompt
- (void)test_companyPortalInstallPrompt
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureMDMEnabled];
    // TODO: remove me once lab is fixed
    configurationRequest.additionalQueryParameters = @{@"AppID": @"4b0db8c2-9f26-4417-8bde-3f0e3656f8e0"};
    [self loadTestConfiguration:configurationRequest];
    
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    [self aadEnterPassword];
    
    XCUIElement *enrollButton = self.testApp.buttons[@"Enroll now"];
    [self waitForElement:enrollButton];
    [enrollButton tap];

    XCUIApplication *safari = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.mobilesafari"];
    BOOL result = [safari waitForState:XCUIApplicationStateRunningForeground timeout:20];
    XCTAssertTrue(result);
    
    XCUIElement *getTheAppButton = safari.staticTexts[@"GET THE APP"];
    [self waitForElement:getTheAppButton];
    
    [self.testApp activate];
}

- (void)testSilentAADLogin_withNoTokensInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *silentParams = @{
                                   @"user_identifier" : self.primaryAccount.account,
                                   @"client_id" : self.testConfiguration.clientId,
                                   @"authority" : self.testConfiguration.authority,
                                   @"resource" : self.testConfiguration.resource
                                   };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
    [self acquireTokenSilent:config];
    [self assertError:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
}

- (void)testSilentAADLogin_withNoUserProvided_multipleUsersInCache
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    // User 1.
    NSMutableDictionary *params = [@{
                                     @"prompt_behavior" : @"always",
                                     @"validate_authority" : @YES,
                                     @"user_identifier" : self.primaryAccount.account,
                                     @"user_identifier_type" : @"optional_displayable"
                                     } mutableCopy];
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    [self aadEnterPassword];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];

    [self closeResultView];

    // User 2.
    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params[@"user_identifier"] = self.primaryAccount.account;
    NSDictionary *config2 = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config2];

    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];

    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];

    // User 1, silent login.
    self.primaryAccount = self.testConfiguration.accounts[0];
    params[@"user_identifier"] = nil;
    config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireTokenSilent:config];
    [self assertError:@"AD_ERROR_CACHE_MULTIPLE_USERS"];
}

- (void)DISABLED_testAADLogin_withPromptAlways_LoginHint_LoginTakesMoreThanFiveMinutes
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for 5 min"];
    [expectation performSelector:@selector(fulfill) withObject:nil afterDelay:300];
    [self waitForExpectationsWithTimeout:310 handler:nil];

    [self aadEnterEmail];
    [self aadEnterPassword];

    [self assertAccessTokenNotNil];

    [self closeResultView];

    // Acquire token again.
    [self acquireToken:config];

    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)signInWithAnotherAccount
{
    XCUIElement *signIn = self.testApp.staticTexts[@"Sign in with another account"];
    [self waitForElement:signIn];
    [signIn tap];
}

@end
