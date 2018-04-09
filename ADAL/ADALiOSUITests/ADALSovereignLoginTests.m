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

@interface ADALSovereignLoginTests : ADALBaseUITest

@end

@implementation ADALSovereignLoginTests

- (void)setUp
{
    [super setUp];

    [self clearCache];
    [self clearCookies];

    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderBlackForest;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 13
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    XCUIElement *emailTextField = self.testApp.textFields[@"Email or phone"];
    [self waitForElement:emailTextField];
    [self.testApp.buttons[@"Next"] tap];
    
    [self blackforestComEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

// #290995 iteration 14
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_noLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self blackforestComEnterEmail];
    [self blackforestComEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)blackforestComEnterEmail
{
    XCUIElement *emailTextField = self.testApp.textFields[@"Email or phone"];
    [self waitForElement:emailTextField];
    [emailTextField pressForDuration:0.5f];
    [emailTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.account]];
}

- (void)blackforestComEnterPassword
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [passwordTextField pressForDuration:0.5f];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
