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

@interface ADALAADInteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALAADInteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    self.accountInfo = [self.accountsProvider testAccountOfType:ADTestAccountTypeAAD];
    self.baseConfigParams = [self basicConfig];
    
    [self clearCache];
    [self clearCookies];
}

#pragma mark - Tests

// #290995 iteration 1
- (void)testInteractiveAADLogin_withPromptAlways_noLoginHint_ADALWebView
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.testUserType = ADUserTypeCloud;
    configurationRequest.sovereignEnvironment = ADEnvironmentTypeGlobal;

    __block ADTestConfiguration *testConfig = nil;

    XCTestExpectation *expectation = [self expectationWithDescription:@"Get configuration"];

    [self.accountsProvider configurationWithRequest:configurationRequest
                                  completionHandler:^(ADTestConfiguration *configuration) {

                                      testConfig = configuration;

                                      [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:60 handler:nil];

    if (!testConfig || ![testConfig.accounts count])
    {
        XCTAssertTrue(NO);
    }

    expectation = [self expectationWithDescription:@"Get password"];

    [self.accountsProvider passwordForAccount:testConfig.accounts[0]
                            completionHandler:^(NSString *password) {

                                [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:60 handler:nil];

    if (![testConfig.accounts[0] password])
    {
        XCTAssertTrue(NO);
    }

    self.testConfiguration = testConfig;
    self.accountInfo = self.testConfiguration.accounts[0];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    
    [self assertAuthUIAppear];
}

// #290995 iteration 2
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSString *jsonString = [self configParamsJsonString:params];
    
    [self acquireToken:jsonString];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];;
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:jsonString];
    
    [self assertAuthUIAppear];
}

// #290995 iteration 3
- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSString *jsonString = [self configParamsJsonString:params];
    
    [self acquireToken:jsonString];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:jsonString];
    
    // Wait for result immediately, no user action required.
    [self assertAccessTokenNotNil];
}

// #290995 iteration 4
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_PassedInWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"web_view" : @"passed_in"
                             };
    NSString *jsonString = [self configParamsJsonString:params];
    
    [self acquireToken:jsonString];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:jsonString];
    
    [self assertAuthUIAppear];
}

// #296277: FoCI: Acquire a token using an FRT
- (void)testAADLogin_withPromptAlways_noLoginHint_acquireTokenUsingFRT
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };
    NSString *jsonString = [self configParamsJsonString:params];
    
    [self acquireToken:jsonString];
    
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:jsonString];
    
    [self assertAuthUIAppear];
    [self closeAuthUI];
    [self closeResultView];
    
    jsonString = [self configParamsJsonString:[self fociConfig] additionalParams:params];
    
    [self acquireTokenSilent:jsonString];
    
    [self assertAccessTokenNotNil];
}

// #296755: FoCI : MRRT Fallback when FRT Fails

- (void)testAADLogin_withPromptAlways_noLoginHint_MRRTFallbackWhenFRTFails
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };
    NSString *jsonString = [self configParamsJsonString:[self fociConfig] additionalParams:params];
    
    [self acquireToken:jsonString];
    
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    NSDictionary *keyParams = @{
                                @"user_id" : self.accountInfo.account,
                                @"client_id" : @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                                @"authority" : @"https://login.windows.net/common",
                                @"resource" : @"https://graph.windows.net"
                                };
    
    [self expireAccessToken:[keyParams toJsonString]];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    keyParams = @{
                  @"user_id" : self.accountInfo.account,
                  @"client_id" : @"foci-1",
                  @"authority" : @"https://login.windows.net/common"
                  };
    
    [self invalidateRefreshToken:[keyParams toJsonString]];
    [self assertRefreshTokenInvalidated];
    [self closeResultView];
    
    [self acquireTokenSilent:jsonString];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// #296753: Login Multiple Accounts
- (void)testAADLogin_withPromptAlways_LoginHint_loginMultipleAccounts
{
    NSArray *accounts = [self.accountsProvider testAccountsOfType:ADTestAccountTypeAAD];
    XCTAssertTrue(accounts.count > 1);
    self.accountInfo = [accounts firstObject];
    
    // User 1.
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    [self.baseConfigParams addEntriesFromDictionary:params];
    NSString *jsonString = [self.baseConfigParams toJsonString];
    
    [self acquireToken:jsonString];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    // User 2.
    ADTestAccount *accountInfo2 = accounts[1];
    self.baseConfigParams[@"user_identifier"] = accountInfo2.account;
    NSString *jsonString2 = [self.baseConfigParams toJsonString];
    
    [self acquireToken:jsonString2];
    
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", accountInfo2.password]];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];
    
    // User 1, silent login.
    [self acquireTokenSilent:jsonString];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // User 2, silent login.
    [self acquireTokenSilent:jsonString2];
    [self assertAccessTokenNotNil];
}

// #296758: Different ADUserIdentifierType settings
- (void)testAADLogin_withPromptAlways_LoginHint_differentUserTypeSettings
{
    NSArray *accounts = [self.accountsProvider testAccountsOfType:ADTestAccountTypeAAD];
    XCTAssertTrue(accounts.count > 1);
    self.accountInfo = [accounts firstObject];
    ADTestAccount *accountInfo2 = accounts[1];
    
    // Optional Displayable, User 1.
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    [self.baseConfigParams addEntriesFromDictionary:params];
    
    [self acquireToken:[self.baseConfigParams toJsonString]];
    
    [self signInWithAnotherAccount];
    
    // User 2.
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", accountInfo2.account]];
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", accountInfo2.password]];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    // Required Displayable, User 1.
    self.baseConfigParams[@"user_identifier_type"] = @"required_displayable";

    [self acquireToken:[self.baseConfigParams toJsonString]];

    [self signInWithAnotherAccount];
    
    // User 2.
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", accountInfo2.account]];
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", accountInfo2.password]];
    
    [self assertError:@"AD_ERROR_SERVER_WRONG_USER"];
    [self closeResultView];
    
    // Sign in with User 1.
    
    [self acquireToken:[self.baseConfigParams toJsonString]];
    
    [self signInWithAnotherAccount];
    
    // User 2.
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// 296732: Company Portal Install Prompt
- (void)test_companyPortalInstallPrompt
{
    self.baseConfigParams = [[self.accountsProvider testProfileOfType:ADTestProfileTypeBasicMDM] mutableCopy];
    NSArray *accounts = [self.accountsProvider testAccountsOfType:ADTestAccountTypeAADMDM];
    XCTAssertTrue(accounts.count > 0);
    self.accountInfo = [accounts firstObject];
    
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.accountInfo.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSString *jsonString = [self configParamsJsonString:params];
    
    [self acquireToken:jsonString];
    
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

#pragma mark - Private

- (void)signInWithAnotherAccount
{
    XCUIElement *signIn = self.testApp.staticTexts[@"Sign in with another account"];
    [self waitForElement:signIn];
    [signIn tap];
}

- (void)aadEnterPassword
{
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.accountInfo.password]];
}

- (void)aadEnterPassword:(NSString *)password
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [passwordTextField pressForDuration:0.5f];
    [passwordTextField typeText:password];
}

@end
