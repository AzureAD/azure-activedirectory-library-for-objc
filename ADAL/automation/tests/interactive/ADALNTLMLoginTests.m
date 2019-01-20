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
#import "XCUIElement+CrossPlat.h"

@interface ADALNTLMLoginTests : ADALBaseUITest

@end

@implementation ADALNTLMLoginTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderNTLM;
    configurationRequest.appVersion = MSIDAppVersionV1;
    configurationRequest.needsMultipleUsers = NO;
    configurationRequest.accountFeatures = @[MSIDTestAccountFeatureNTLM];
    [self loadTestConfiguration:configurationRequest];
}


// TODO: enable NTLM tests once NTLM environment is available
- (void)DISABLED_testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *request = [MSIDAutomationTestRequest new];
    request.uiBehavior = @"always";
    request.validateAuthority = NO;
    request.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self ntlmWaitForAlert];
    [self ntlmEnterUsername];
    [self ntlmEnterPassword];
    [self ntlmLogin];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:config];

    // Because of cookies, request should be satisfied automatically
    [self assertAccessTokenNotNil];
}

- (void)DISABLED_testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_PassedInWebView
{
    MSIDAutomationTestRequest *request = [MSIDAutomationTestRequest new];
    request.uiBehavior = @"always";
    request.validateAuthority = NO;
    request.usePassedWebView = YES;
    request.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self ntlmWaitForAlert];
    [self ntlmEnterUsername];
    [self ntlmEnterPassword];
    [self ntlmLogin];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)DISABLED_testInteractiveNTLMLogin_withPromptAlways_withoutLoginHint_ADALWebView_andCancelAuth
{
    MSIDAutomationTestRequest *request = [MSIDAutomationTestRequest new];
    request.uiBehavior = @"always";
    request.validateAuthority = NO;
    request.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self ntlmWaitForAlert];
    [self ntlmCancel];
    [self closeAuthUI];
    
    [self assertErrorCode:@"AD_ERROR_UI_USER_CANCEL"];
    
    [self closeResultView];
    
    [self acquireToken:config];
    
    [self ntlmWaitForAlert];
}

#pragma mark - Helpers

- (void)ntlmWaitForAlert
{
    [self waitForElement:[self ntlmAlert]];
}

- (void)ntlmEnterUsername
{
    XCUIElement *usernameField = [self.testApp.textFields element];
    [self tapElementAndWaitForKeyboardToAppear:usernameField];
    [usernameField activateTextField];
    [usernameField typeText:self.primaryAccount.account];
}

- (void)ntlmEnterPassword
{
    XCUIElement *passwordField = [self.testApp.secureTextFields element];
    [self tapElementAndWaitForKeyboardToAppear:passwordField];
    [passwordField activateTextField];
    [passwordField typeText:self.primaryAccount.password];
}

- (void)ntlmLogin
{
    [[self ntlmAlert].buttons[@"Login"] msidTap];
}

- (void)ntlmCancel
{
    [[self ntlmAlert].buttons[@"Cancel"] msidTap];
}

- (XCUIElement *)ntlmAlert
{
#if TARGET_OS_IPHONE
    return self.testApp.alerts[@"Enter your credentials"];
#else
    return self.testApp.sheets.firstMatch;
#endif
}

@end
