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

@interface ADALNTLMLoginTests : ADALBaseUITest

@end

@implementation ADALNTLMLoginTests

- (void)setUp
{
    [super setUp];

    [self clearCache];
    [self clearCookies];

    MSIDTestConfigurationRequest *configurationRequest = [MSIDTestConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderNTLM;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.needsMultipleUsers = NO;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureNTLM];
    [self loadTestConfiguration:configurationRequest];
}


- (void)testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"user_identifier_type" : @"optional_displayable",
                             @"validate_authority" : @NO
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    [self acquireToken:configJson];

    [self ntlmWaitForAlert];
    [self ntlmEnterUsername];
    [self ntlmEnterPassword];
    [self ntlmLogin];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:configJson];

    [self assertAuthUIAppear];
}

- (void)testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_PassedInWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"user_identifier_type" : @"optional_displayable",
                             @"validate_authority" : @NO,
                             @"web_view" : @"passed_in"
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    [self acquireToken:configJson];

    [self ntlmWaitForAlert];
    [self ntlmEnterUsername];
    [self ntlmEnterPassword];
    [self ntlmLogin];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

- (void)testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_ADALWebView_andCancelAuth
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"user_identifier_type" : @"optional_displayable",
                             @"validate_authority" : @NO
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    [self acquireToken:configJson];

    [self ntlmWaitForAlert];
    [self ntlmCancel];
    [self assertError:@"AD_ERROR_UI_USER_CANCEL"];
}

#pragma mark - Helpers

- (void)ntlmWaitForAlert
{
    XCUIElement *ntlmAlert = self.testApp.alerts[@"Enter your credentials"];
    [self waitForElement:ntlmAlert];
}

- (void)ntlmEnterUsername
{
    XCUIElement *usernameField = [self.testApp.textFields firstMatch];
    [usernameField pressForDuration:0.5f];
    [usernameField typeText:self.primaryAccount.account];
}

- (void)ntlmEnterPassword
{
    XCUIElement *passwordField = [self.testApp.secureTextFields firstMatch];
    [passwordField pressForDuration:0.5f];
    [passwordField typeText:self.primaryAccount.password];
}

- (void)ntlmLogin
{
    XCUIElement *ntlmAlert = self.testApp.alerts[@"Enter your credentials"];
    [ntlmAlert.buttons[@"Login"] tap];
}

- (void)ntlmCancel
{
    XCUIElement *ntlmAlert = self.testApp.alerts[@"Enter your credentials"];
    [ntlmAlert.buttons[@"Cancel"] tap];
}

@end
