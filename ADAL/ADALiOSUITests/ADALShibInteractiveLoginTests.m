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

@interface ADALShibInteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALShibInteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    [self clearCache];
    [self clearCookies];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderShibboleth;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 5
- (void)testInteractiveShibLogin_withPromptAlways_noLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    
    [self aadEnterEmail];
    
    [self shibEnterUsername];
    [self shibEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
}

// #290995 iteration 6
- (void)testInteractiveShibLogin_withPromptAlways_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    [self acquireToken:config];
    
    [self shibEnterUsername];
    [self shibEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)shibEnterUsername
{
    XCUIElement *usernameTextField = [self.testApp.textFields firstMatch];
    [self waitForElement:usernameTextField];
    [self tapElementAndWaitForKeyboardToAppear:usernameTextField];
    [usernameTextField typeText:self.primaryAccount.username];
}

- (void)shibEnterPassword
{
    XCUIElement *passwordTextField = [self.testApp.secureTextFields firstMatch];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
