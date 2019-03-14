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

@interface ADALSovereignLoginTests : ADALBaseUITest

@end

@implementation ADALSovereignLoginTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderBlackForest;
    configurationRequest.needsMultipleUsers = NO;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 13
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_withLoginHint_ADALWebView
{
    // Do interactive login
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.loginHint = self.primaryAccount.account;
    request.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:self.class.confProvider.wwEnvironment];
    request.requestResource = [self.class.confProvider resourceForEnvironment:@"de" type:@"aad_graph"];
    request.legacyAccountIdentifierType = @"required_displayable";
    request.extraQueryParameters = @{@"instance_aware": @1};
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];

    [self blackForestWaitForNextButton:self.testApp];
    [self blackforestComEnterPassword];
    
    NSString *userId = [self runSharedResultAssertionWithTestRequest:request];
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
    
    // Do UI appears test
    [self runSharedAuthUIAppearsStepWithTestRequest:request];

    // First try silent with (wrong) WW authority
    request.legacyAccountIdentifier = userId;
    NSDictionary *silentWWConfig = [self configWithTestRequest:request];
    [self acquireTokenSilent:silentWWConfig];
    [self assertErrorCode:@"AD_ERROR_SERVER_USER_INPUT_NEEDED"];
    [self closeResultView];

    // Now try silent with correct blackforest authority - #296889
    request.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:@"de"];
    [self runSharedSilentLoginWithTestRequest:request];
}

// #290995 iteration 14
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_noLoginHint_ADALWebView
{
    // Do interactive login
    MSIDAutomationTestRequest *request = [self.class.confProvider defaultAppRequest];
    request.promptBehavior = @"always";
    request.configurationAuthority = [self.class.confProvider defaultAuthorityForIdentifier:self.class.confProvider.wwEnvironment];
    request.extraQueryParameters = @{@"instance_aware": @1};
    request.requestResource = [self.class.confProvider resourceForEnvironment:@"de" type:@"aad_graph"];
    
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    
    [self blackforestComEnterEmail];
    [self blackforestComEnterPassword];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)blackforestComEnterEmail
{
    XCUIElement *emailTextField = self.testApp.textFields[@"Enter your email, phone, or Skype."];
    [self waitForElement:emailTextField];
    [self tapElementAndWaitForKeyboardToAppear:emailTextField];
    [emailTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.account]];
}

- (void)blackforestComEnterPassword
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields.firstMatch;
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
