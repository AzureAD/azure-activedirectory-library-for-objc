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
    
    [self clearCache];
    [self clearCookies];
}

#pragma mark - Tests

// #290995 iteration 1
- (void)testInteractiveAADLogin_withPromptAlways_noLoginHint_ADALWebView
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

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
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];;
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    
    [self assertAuthUIAppear];
}

// #290995 iteration 3
- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_ADALWebView
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    
    // Wait for result immediately, no user action required.
    [self assertAccessTokenNotNil];
}

// #290995 iteration 4
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_PassedInWebView
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"web_view" : @"passed_in"
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    
    [self assertAuthUIAppear];
}

// #296277: FoCI: Acquire a token using an FRT
- (void)testAADLogin_withPromptAlways_noLoginHint_acquireTokenUsingFRT
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: add foci support to the lab API
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                             };

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
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

    NSString *configJson2 = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];

    [self acquireTokenSilent:configJson2];
    [self assertAccessTokenNotNil];
}

// #296755: FoCI : MRRT Fallback when FRT Fails
- (void)testAADLogin_withPromptAlways_noLoginHint_MRRTFallbackWhenFRTFails
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: add foci support to the lab API
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                             @"redirect_uri": @"urn:ietf:wg:oauth:2.0:oob",
                             };

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterEmail];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    NSDictionary *keyParams = @{
                                @"user_id" : self.primaryAccount.account,
                                @"client_id" : @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                                @"authority" : self.testConfiguration.authority,
                                @"resource" : self.testConfiguration.resource
                                };
    
    [self expireAccessToken:[keyParams toJsonString]];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    keyParams = @{
                  @"user_id" : self.primaryAccount.account,
                  @"client_id" : @"foci-1",
                  @"authority" : self.testConfiguration.authority
                  };
    
    [self invalidateRefreshToken:[keyParams toJsonString]];
    [self assertRefreshTokenInvalidated];
    [self closeResultView];
    
    [self acquireTokenSilent:configJson];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// #296753: Login Multiple Accounts
- (void)testAADLogin_withPromptAlways_LoginHint_loginMultipleAccounts
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.needsMultipleUsers = YES;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    // TODO: remove this, once API is fixed to return multiple accounts
    [self.testConfiguration addAdditionalAccount:self.accountsProvider.defaultLabAccount];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    // User 1.
    NSMutableDictionary *params = [@{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             } mutableCopy];
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    
    [self closeResultView];
    
    // User 2.
    self.primaryAccount = self.testConfiguration.accounts[1];
    [self loadPasswordForAccount:self.primaryAccount];

    params[@"user_identifier"] = self.primaryAccount.account;
    NSString *configJson2 = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    [self acquireToken:configJson2];
    
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
    [self closeResultView];
    
    // User 1, silent login.
    self.primaryAccount = self.testConfiguration.accounts[0];
    params[@"user_id"] = self.primaryAccount.account;
    configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    [self expireAccessToken:configJson];
    [self assertAccessTokenExpired];
    [self closeResultView];

    [self acquireTokenSilent:configJson];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // User 2, silent login.
    [self acquireTokenSilent:configJson2];
    [self assertAccessTokenNotNil];
}

// #296758: Different ADUserIdentifierType settings
- (void)testAADLogin_withPromptAlways_LoginHint_differentUserTypeSettings
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    configurationRequest.needsMultipleUsers = YES;
    [self loadTestConfiguration:configurationRequest];

    // TODO: remove this, once API is fixed to return multiple users
    [self.testConfiguration addAdditionalAccount:self.accountsProvider.defaultAccount];

    XCTAssertTrue([self.testConfiguration.accounts count] >= 2);

    ADTestAccount *firstAccount = self.testConfiguration.accounts[0];
    ADTestAccount *secondaryAccount = self.testConfiguration.accounts[1];

    // Optional Displayable, User 1.
    NSMutableDictionary *params = [@{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : secondaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             } mutableCopy];

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];

    [self acquireToken:configJson];

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

    NSString *configJson2 = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];

    [self acquireToken:configJson2];

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
    NSString *configJson3 = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];

    [self acquireToken:configJson3];
    [self aadEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self assertRefreshTokenNotNil];
}

// 296732: Company Portal Install Prompt
- (void)test_companyPortalInstallPrompt
{
    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderWW;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    configurationRequest.accountFeatures = @[ADTestAccountFeatureMDMEnabled];
    configurationRequest.additionalQueryParameters = @{@"AppID": @"4b0db8c2-9f26-4417-8bde-3f0e3656f8e0"};
    [self loadTestConfiguration:configurationRequest];
    
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
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
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

- (void)aadEnterPassword:(NSString *)password
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [passwordTextField pressForDuration:0.5f];
    [passwordTextField typeText:password];
}

@end
