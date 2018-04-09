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

@interface ADALPingInteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALPingInteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    [self clearCache];
    [self clearCookies];

    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    //TODO: uncomment me once Ping accounts are available
    //configurationRequest.accountProvider = ADTestAccountProviderPing;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 9
- (void)testInteractivePingLogin_withPromptAlways_noLoginHint_ADALWebView
{
    // TODO: remove me once Ping accounts are available in lab
    self.primaryAccount = self.accountsProvider.defaultPingAccount;
    [self loadPasswordForAccount:self.primaryAccount];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707", // TODO: remove me once Ping accounts are available
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive" // TODO: remove me once Ping accounts are available
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterEmail];
    
    [self pingEnterUsername];
    [self pingEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

// #290995 iteration 10
- (void)testInteractivePingLogin_withPromptAlways_withLoginHint_ADALWebView
{
    // TODO: remove me once Ping accounts are available in lab
    self.primaryAccount = self.accountsProvider.defaultPingAccount;
    [self loadPasswordForAccount:self.primaryAccount];

    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707", // TODO: remove me once Ping accounts are available
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive" // TODO: remove me once Ping accounts are available
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self pingEnterUsername];
    [self pingEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    
    // Wait for result, no user action required.
    [self assertAccessTokenNotNil];
}

#pragma mark - Private

- (void)pingEnterUsername
{
    XCUIElement *usernameTextField = [self.testApp.textFields firstMatch];
    [self waitForElement:usernameTextField];
    [usernameTextField pressForDuration:0.5f];
    [usernameTextField typeText:self.primaryAccount.username];
}

- (void)pingEnterPassword
{
    XCUIElement *passwordTextField = [self.testApp.secureTextFields firstMatch];
    [self waitForElement:passwordTextField];
    [passwordTextField pressForDuration:0.5f];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
